use std::io::{Read, Write};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

use crate::{
    crypt::{
        header::{CHUNK_SIZE, FILE_ID_LEN, FileHeader, HEADER_LEN, NONCE_LEN},
        key::{derive_key, derive_nonce, split_keys},
    },
    error::{Error, Result},
};

/// Streaming encryption loop: read plaintext chunks from `reader`, encrypt
/// each with the cipher, and write `[NONCE | CIPHERTEXT | TAG]` to `writer`.
fn encrypt_chunks(
    reader: &mut dyn Read,
    writer: &mut dyn std::io::Write,
    cipher: &XChaCha20Poly1305,
    key_mac: &[u8; 32],
    file_id: &[u8; FILE_ID_LEN],
    header_bytes: &[u8; HEADER_LEN],
) -> Result<()> {
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut out_buf: Vec<u8> = Vec::with_capacity(NONCE_LEN + CHUNK_SIZE + 16);
    let mut aad = {
        let mut aad = [0u8; HEADER_LEN + 9];
        aad[..HEADER_LEN].copy_from_slice(header_bytes);
        aad
    };
    let mut chunk_idx = 0u64;

    loop {
        let mut bytes_read = 0;
        while bytes_read < CHUNK_SIZE {
            let n = reader.read(&mut buffer[bytes_read..])?;
            if n == 0 {
                break;
            }
            bytes_read += n;
        }

        let is_last_chunk = bytes_read < CHUNK_SIZE;
        aad[HEADER_LEN..HEADER_LEN + 8].copy_from_slice(&chunk_idx.to_le_bytes());
        aad[HEADER_LEN + 8] = u8::from(is_last_chunk);

        let nonce_bytes = derive_nonce(key_mac, file_id, &buffer[..bytes_read], chunk_idx);
        let nonce = XNonce::from(nonce_bytes);

        let payload = Payload {
            msg: &buffer[..bytes_read],
            aad: &aad,
        };

        let ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|e| Error::EncryptFailed(e.to_string()))?;

        out_buf.clear();
        out_buf.extend_from_slice(&nonce_bytes);
        out_buf.extend_from_slice(&ciphertext);
        writer.write_all(&out_buf)?;

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
    writer: &mut dyn std::io::Write,
    cipher: &XChaCha20Poly1305,
    header_bytes: &[u8; HEADER_LEN],
) -> Result<()> {
    let mut nonce_buf = [0u8; NONCE_LEN];
    let mut ct_buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE + 16]);
    let ct_len = ct_buffer.len();
    let mut aad = {
        let mut aad = [0u8; HEADER_LEN + 9];
        aad[..HEADER_LEN].copy_from_slice(header_bytes);
        aad
    };
    let mut last_chunk_was_final = false;
    let mut chunk_idx = 0u64;

    loop {
        match reader.read_exact(&mut nonce_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }

        let mut bytes_read = 0;
        while bytes_read < ct_len {
            let n = reader.read(&mut ct_buffer[bytes_read..])?;
            if n == 0 {
                break;
            }
            bytes_read += n;
        }

        if bytes_read == 0 {
            return Err(Error::TruncatedChunk);
        }

        let is_last_chunk = bytes_read < ct_len;

        aad[HEADER_LEN..HEADER_LEN + 8].copy_from_slice(&chunk_idx.to_le_bytes());
        aad[HEADER_LEN + 8] = u8::from(is_last_chunk);

        let nonce = XNonce::from(nonce_buf);
        let payload = chacha20poly1305::aead::Payload {
            msg: &ct_buffer[..bytes_read],
            aad: &aad,
        };

        let plaintext = Zeroizing::new(
            cipher
                .decrypt(&nonce, payload)
                .map_err(|e| Error::DecryptFailed(e.to_string()))?,
        );

        writer.write_all(&plaintext)?;

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
    writer: &mut dyn std::io::Write,
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
pub fn encrypt_into<R: Read, W: std::io::Write>(
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
    let cipher = XChaCha20Poly1305::new(key_enc.as_ref().into());

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
pub fn decrypt_into<R: Read, W: std::io::Write>(
    reader: &mut R,
    writer: &mut W,
    master_key: &[u8],
) -> Result<FileHeader> {
    let header = FileHeader::read_from(reader)?;

    let derived_key = derive_key(master_key, &header.salt)?;
    let (key_enc, _) = split_keys(&derived_key);
    let cipher = XChaCha20Poly1305::new(key_enc.as_ref().into());

    decrypt_body(reader, writer, &cipher, &header)?;
    Ok(header)
}
