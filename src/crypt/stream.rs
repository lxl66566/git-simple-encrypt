use std::io::{Read, Write};

use chacha20poly1305_simd::XChaCha20Poly1305;
use zeroize::Zeroizing;

use crate::{
    crypt::{
        header::{CHUNK_SIZE, FILE_ID_LEN, FileHeader, HEADER_LEN, NONCE_LEN},
        key::{derive_key, derive_nonce, split_key_enc, split_keys},
    },
    error::{Error, Result},
};

/// Streaming encryption loop: read plaintext chunks from `reader`, encrypt
/// each with the cipher, and write `[NONCE | CIPHERTEXT | TAG]` to `writer`.
fn encrypt_chunks(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    cipher: &XChaCha20Poly1305,
    key_mac: &[u8; 32],
    file_id: &[u8; FILE_ID_LEN],
    header_bytes: &[u8; HEADER_LEN],
) -> Result<()> {
    // Reusable buffer laid out as `[NONCE | chunk | TAG]`, so each chunk
    // reaches the writer as ONE contiguous `write_all`. The previous layout
    // issued a 24 B nonce write + a payload write per chunk via vectored IO —
    // fine where writev exists, but on Windows files it degrades to two
    // syscalls per chunk. The detached AEAD variant encrypts a plain
    // `&mut [u8]` window in place (no `Buffer` growth needed), the tag is
    // copied into the reserved tail, and the physical chunk format is
    // unchanged. Zero allocation and zero chunk-sized copies per iteration.
    const TAG_LEN: usize = 16;
    let mut buffer: Zeroizing<Vec<u8>> =
        Zeroizing::new(Vec::with_capacity(NONCE_LEN + CHUNK_SIZE + TAG_LEN));
    let mut aad = {
        let mut aad = [0u8; HEADER_LEN + 9];
        aad[..HEADER_LEN].copy_from_slice(header_bytes);
        aad
    };
    let mut chunk_idx = 0u64;

    loop {
        // Restore a full CHUNK_SIZE window for reading; `truncate` below
        // changes the length each iteration, so resize at the top.
        buffer.resize(NONCE_LEN + CHUNK_SIZE, 0);
        let mut bytes_read = 0;
        while bytes_read < CHUNK_SIZE {
            let n = reader.read(&mut buffer[NONCE_LEN + bytes_read..NONCE_LEN + CHUNK_SIZE])?;
            if n == 0 {
                break;
            }
            bytes_read += n;
        }

        let is_last_chunk = bytes_read < CHUNK_SIZE;
        aad[HEADER_LEN..HEADER_LEN + 8].copy_from_slice(&chunk_idx.to_le_bytes());
        aad[HEADER_LEN + 8] = u8::from(is_last_chunk);

        let (nonce_head, chunk) = buffer.split_at_mut(NONCE_LEN);
        let chunk = &mut chunk[..bytes_read];

        // Nonce is derived from the *plaintext* chunk, so compute it before
        // the detached encrypt overwrites the window with ciphertext.
        let nonce = derive_nonce(key_mac, file_id, chunk, chunk_idx);
        nonce_head.copy_from_slice(&nonce);

        let tag = cipher
            .encrypt_in_place_detached(&nonce, &aad, chunk)
            .map_err(|e| Error::EncryptFailed(e.to_string()))?;

        // Exactly `[NONCE | CIPHERTEXT | TAG]`, one write.
        buffer.truncate(NONCE_LEN + bytes_read);
        buffer.extend_from_slice(&tag);
        writer.write_all(&buffer)?;

        chunk_idx += 1;

        if is_last_chunk {
            break;
        }
    }

    Ok(())
}

/// Streaming decryption loop: read encrypted chunks from `reader`, decrypt,
/// and write plaintext to `writer`.
///
/// Chunk layout: `[NONCE (24B)] [CIPHERTEXT] [TAG (16B)]`
fn decrypt_chunks(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    cipher: &XChaCha20Poly1305,
    header_bytes: &[u8; HEADER_LEN],
) -> Result<()> {
    // Each encrypted chunk is plaintext (<= CHUNK_SIZE) + 16 B tag.
    // `decrypt_in_place` overwrites it in place with the plaintext and
    // strips the tag, so this single buffer is reused for every chunk — no
    // per-chunk Vec allocation.
    const TAG_LEN: usize = 16;
    let ct_len = CHUNK_SIZE + TAG_LEN;
    let mut nonce_buf = [0u8; NONCE_LEN];
    let mut ct_buffer: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(ct_len));
    let mut aad = {
        let mut aad = [0u8; HEADER_LEN + 9];
        aad[..HEADER_LEN].copy_from_slice(header_bytes);
        aad
    };
    let mut last_chunk_was_final = false;
    let mut chunk_idx = 0u64;

    loop {
        match reader.read_exact(&mut nonce_buf) {
            Ok(()) => {},
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }

        ct_buffer.resize(ct_len, 0);
        let mut bytes_read = 0;
        while bytes_read < ct_len {
            let n = reader.read(&mut ct_buffer[bytes_read..])?;
            if n == 0 {
                break;
            }
            bytes_read += n;
        }

        if bytes_read < TAG_LEN {
            return Err(Error::TruncatedChunk);
        }

        let is_last_chunk = bytes_read < ct_len;
        ct_buffer.truncate(bytes_read);

        aad[HEADER_LEN..HEADER_LEN + 8].copy_from_slice(&chunk_idx.to_le_bytes());
        aad[HEADER_LEN + 8] = u8::from(is_last_chunk);

        cipher
            .decrypt_in_place(&nonce_buf, &aad, &mut *ct_buffer)
            .map_err(|e| Error::DecryptFailed(e.to_string()))?;

        writer.write_all(&ct_buffer)?;

        chunk_idx += 1;

        if is_last_chunk {
            last_chunk_was_final = true;
            break;
        }
    }

    if !last_chunk_was_final {
        return Err(Error::FileTruncated);
    }

    Ok(())
}

/// Decrypt the body (with optional Zstd decompression)
pub(super) fn decrypt_body(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    cipher: &XChaCha20Poly1305,
    header: &FileHeader,
) -> Result<()> {
    if header.is_compressed() {
        let mut decoder = zstd::stream::write::Decoder::new(writer)?.auto_flush();
        decrypt_chunks(reader, &mut decoder, cipher, header.as_bytes())?;
        decoder.flush()?;
    } else {
        decrypt_chunks(reader, writer, cipher, header.as_bytes())?;
    }
    Ok(())
}

/// Encrypt data from `reader` into `writer` using streaming chunked encryption.
pub fn encrypt_into<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    derived_key: &[u8; 32],
    salt: [u8; crate::crypt::header::SALT_LEN],
    file_id: Option<[u8; FILE_ID_LEN]>,
    zstd: Option<u8>,
) -> Result<FileHeader> {
    let file_id = file_id.unwrap_or_else(FileHeader::generate_file_id);
    let header = FileHeader::new(zstd.is_some(), salt, file_id);
    header.write_to(writer)?;

    let (key_enc, key_mac) = split_keys(derived_key);
    let cipher = XChaCha20Poly1305::new(*key_enc);

    if let Some(level) = zstd {
        let mut encoder = zstd::stream::read::Encoder::new(reader, i32::from(level))?;
        encrypt_chunks(
            &mut encoder,
            writer,
            &cipher,
            &key_mac,
            &file_id,
            header.as_bytes(),
        )?;
    } else {
        encrypt_chunks(
            reader,
            writer,
            &cipher,
            &key_mac,
            &file_id,
            header.as_bytes(),
        )?;
    }

    Ok(header)
}

/// Decrypt data from `reader` into `writer`.
pub fn decrypt_into<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    master_key: &[u8],
) -> Result<FileHeader> {
    let header = FileHeader::read_from(reader)?;

    let derived_key = derive_key(master_key, &header.salt)?;
    let key_enc = split_key_enc(&derived_key);
    let cipher = XChaCha20Poly1305::new(*key_enc);

    decrypt_body(reader, writer, &cipher, &header)?;
    Ok(header)
}
