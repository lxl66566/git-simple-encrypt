//! The core of this program. Encrypt/decrypt, compress/decompress files.
//!
//! GITSE Binary Header Layout (64 Bytes)
//!  00          04  05  06  07           17                  27              3F
//!  +-----------+---+---+---+-----------+-------------------+---------------+
//!  |   MAGIC   | V | F | A |   SALT    |     `FILE_ID`     |   RESERVED    |
//!  |  "GITSE"  |   |   |   | (16 bytes)|    (16 bytes)     |  (24 bytes)   |
//!  +-----------+---+---+---+-----------+-------------------+---------------+
//!    5 bytes     1   1   1    16 bytes       16 bytes          24 bytes
//!                |   |   |
//!     Version ---+   |   +--- Encryption Algo (1 = XChaCha20-Poly1305 Stream)
//!                    |
//!      Flags --------+ (Bit 0: Compression)
//!
//! Streaming Format:
//! Files are processed in 64KB chunks.
//! Each chunk is individually encrypted using XChaCha20-Poly1305.
//!
//! # Nonce Derivation (Content-Based with File ID)
//!
//! Per-chunk nonces are derived from the file's random `File_ID` and the
//! chunk's own plaintext content using keyed Blake3:
//!
//! 1. A random 16-byte `File_ID` is generated once per file and stored in the
//!    header. This ensures that even if two different files have identical
//!    plaintext at chunk 0, they produce different nonces and ciphertexts.
//! 2. The Argon2-derived master key is split via `blake3::derive_key` into
//!    `Key_ENC` (for XChaCha20-Poly1305 encryption) and `Key_MAC` (for nonce
//!    generation).
//! 3. For each chunk `i`: `Nonce_i = Blake3_keyed(Key_MAC, File_ID || M_i ||
//!    chunk_idx_le)[0..24]`
//! 4. The 24-byte nonce is stored in plaintext at the head of each encrypted
//!    chunk.
//!
//! Different plaintext always produces a different nonce (within the same
//! file). The `File_ID` ensures cross-file uniqueness. The chunk index prevents
//! reordering attacks on identical 64 KB blocks.
//!
//! # Authenticated Additional Data (AAD)
//!
//! Each chunk's AAD binds the ciphertext to the full file header so that any
//! tampering with header fields (version, compression flag, salt, `file_id`,
//! reserved) is detected via Poly1305 authentication failure:
//!
//! ```text
//! AAD = HEADER (64B) || chunk_idx (8B LE) || is_last_chunk (1B)   // 73 bytes
//! ```
//!
//! Each encrypted chunk layout: `[NONCE (24B)] [CIPHERTEXT] [TAG (16B)]`

use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use argon2::Argon2;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use dashmap::DashMap;
use log::{debug, warn};
use pathdiff::diff_paths;
use rand::prelude::*;
use rayon::prelude::*;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use crate::{
    error::{Error, Result},
    repo::Repo,
    salt_cache::{self, CacheRef, CachedEntry},
    utils::{
        Progress, is_file_encrypted, print_post_report, print_pre_report, resolve_target_files,
    },
};

// --- Constants & Header Layout ---

pub const MAGIC: &[u8; 5] = b"GITSE";
/// Current encryption format version.
pub const VERSION: u8 = 3;
const FLAG_COMPRESSED: u8 = 1 << 0; // Bit 0
const ENC_ALGO: u8 = 1; // 1 = XChaCha20-Poly1305

// Sizes
pub const SALT_LEN: usize = 16;
pub const FILE_ID_LEN: usize = 16;
pub const NONCE_LEN: usize = 24; // XChaCha20 uses a 192-bit (24-byte) nonce
pub const HEADER_LEN: usize = 64;
const RESERVED_LEN: usize = HEADER_LEN - (MAGIC.len() + 1 + 1 + 1 + SALT_LEN + FILE_ID_LEN); // 24 bytes

// Streaming
const CHUNK_SIZE: usize = 65536; // 64 KB chunks

/// Returns `true` if the given version byte is supported for decryption.
#[inline]
#[must_use]
pub const fn is_encrypted_version(v: u8) -> bool {
    v == VERSION
}

// --- Helper Structures ---

/// Fixed-size file header stored at the beginning of every encrypted file.
///
/// The layout is `#[repr(C)]` with all fields being `u8` or `[u8; N]`, so:
/// - **Alignment** = 1 (same as `u8`)
/// - **Size** = exactly `HEADER_LEN` (64 bytes)
/// - **No padding** — the compiler cannot insert any between `u8`-aligned
///   fields
///
/// This makes zero-copy casting to/from `[u8; HEADER_LEN]` sound, verified by
/// the compile-time assertions below.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileHeader {
    magic: [u8; 5],
    version: u8,
    flags: u8,
    enc_algo: u8,
    salt: [u8; SALT_LEN],
    file_id: [u8; FILE_ID_LEN],
    reserved: [u8; RESERVED_LEN],
}

// Compile-time safety invariants for zero-copy casting.
const _: () = assert!(std::mem::size_of::<FileHeader>() == HEADER_LEN);
const _: () = assert!(std::mem::align_of::<FileHeader>() == 1);

impl FileHeader {
    /// Construct a header with explicit `file_id`. Callers are responsible for
    /// generating (or looking up the cached) `file_id` so that re-encryption is
    /// deterministic.
    #[must_use]
    pub const fn new(compressed: bool, salt: [u8; SALT_LEN], file_id: [u8; FILE_ID_LEN]) -> Self {
        let mut flags = 0u8;
        if compressed {
            flags |= FLAG_COMPRESSED;
        }

        Self {
            magic: *MAGIC,
            version: VERSION,
            flags,
            enc_algo: ENC_ALGO,
            salt,
            file_id,
            reserved: [0u8; RESERVED_LEN],
        }
    }

    /// Generate a fresh random `file_id` using the system RNG.
    #[must_use]
    pub fn generate_file_id() -> [u8; FILE_ID_LEN] {
        let mut rng = rand::rng();
        let mut id = [0u8; FILE_ID_LEN];
        rng.fill_bytes(&mut id);
        id
    }

    /// Zero-copy: validate and cast `&[u8; 64]` → `&FileHeader`.
    ///
    /// The returned reference borrows from `bytes` — no allocation or copying.
    pub fn from_bytes(bytes: &[u8; HEADER_LEN]) -> Result<&Self> {
        // SAFETY: FileHeader is #[repr(C)] with only u8/[u8; N] fields.
        // Alignment == 1, size == HEADER_LEN, no padding — verified by the
        // compile-time assertions above.
        let header: &Self = unsafe { &*(bytes.as_ptr().cast()) };

        if &header.magic != MAGIC {
            return Err(Error::InvalidMagic);
        }
        if !is_encrypted_version(header.version) {
            return Err(Error::UnsupportedVersion(header.version));
        }
        if header.enc_algo != ENC_ALGO {
            return Err(Error::UnsupportedAlgo(header.enc_algo));
        }

        Ok(header)
    }

    /// Read 64 bytes from `reader`, validate, and return an owned header.
    ///
    /// This is a convenience wrapper around [`from_bytes`](Self::from_bytes)
    /// for callers that already have a `Read` impl (e.g. integration tests).
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let mut buf = [0u8; HEADER_LEN];
        reader.read_exact(&mut buf)?;
        Ok(*Self::from_bytes(&buf)?)
    }

    /// Write the header bytes to `writer` (zero-copy via [`as_bytes`]).
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(self.as_bytes())?;
        Ok(())
    }

    /// Zero-copy: view the header as a fixed-size byte slice.
    ///
    /// The returned `&[u8; HEADER_LEN]` borrows from `self`.
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; HEADER_LEN] {
        // SAFETY: Same reasoning as from_bytes — #[repr(C)], align 1,
        // size == HEADER_LEN, no padding.
        unsafe { &*std::ptr::from_ref::<Self>(self).cast() }
    }

    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        (self.flags & FLAG_COMPRESSED) != 0
    }
}

// --- Core Logic ---

/// Derive a 32-byte key from `password` and `salt` using Argon2.
///
/// This is the foundational key-derivation step shared by all encryption and
/// decryption paths. The result is split into `Key_ENC` + `Key_MAC` via
/// [`split_keys`] before use.
///
/// For batch operations, prefer caching the result (one derivation per unique
/// salt) rather than calling this per file.
pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(password, salt, &mut *key)
        .map_err(|e| Error::Argon2(e.to_string()))?;
    Ok(key)
}

/// Split the Argon2-derived master key into `Key_ENC` (encryption) and
/// `Key_MAC` (nonce generation) using blake3's `derive_key` (HKDF-like).
fn split_keys(master_key: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let key_enc = blake3::derive_key("git-simple-encrypt-enc", master_key);
    let key_mac = blake3::derive_key("git-simple-encrypt-mac", master_key);
    (Zeroizing::new(key_enc), Zeroizing::new(key_mac))
}

/// Content-based nonce derivation using keyed Blake3 with `File_ID`.
///
/// Computes: `Blake3_keyed(Key_MAC, File_ID || plaintext ||
/// chunk_idx_le)[0..24]`
///
/// The `File_ID` ensures cross-file uniqueness: even if two different files
/// have identical plaintext at the same chunk index, they produce different
/// nonces. The chunk index prevents reordering attacks on identical 64 KB
/// blocks.
fn derive_nonce(
    key_mac: &[u8; 32],
    file_id: &[u8; FILE_ID_LEN],
    plaintext: &[u8],
    chunk_idx: u64,
) -> [u8; NONCE_LEN] {
    let mut hasher = blake3::Hasher::new_keyed(key_mac);
    hasher.update(file_id);
    hasher.update(plaintext);
    hasher.update(&chunk_idx.to_le_bytes());
    let hash = hasher.finalize();
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&hash.as_bytes()[..NONCE_LEN]);
    nonce
}

/// Persist a `NamedTempFile` to `dst` atomically, optionally copying metadata
/// from `metadata_source`.
///
/// When `metadata_source` is `Some(src)`, the source file's permissions and
/// timestamps are copied onto the temp file before it is renamed to `dst`.
/// Metadata-copy failures are logged as warnings (non-fatal) so that a
/// metadata issue never causes data loss.
fn persist_temp_file(
    temp_file: NamedTempFile,
    dst: &Path,
    metadata_source: Option<&Path>,
) -> Result<()> {
    if let Some(src) = metadata_source
        && let Err(e) = copy_metadata::copy_metadata(src, temp_file.path())
    {
        warn!("Could not copy metadata from {}: {}", src.display(), e);
    }
    temp_file
        .persist(dst)
        .map_err(|e| Error::AtomicPersist(dst.to_path_buf(), e.to_string()))?;
    Ok(())
}

/// Streaming encryption loop: read plaintext chunks from `reader`, encrypt
/// each with the cipher, and write `[NONCE | CIPHERTEXT | TAG]` to `writer`.
///
/// `reader` is the *post-compression* plaintext stream — the caller is
/// responsible for wrapping the raw input in a Zstd encoder if desired.
fn encrypt_chunks(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    cipher: &XChaCha20Poly1305,
    key_mac: &[u8; 32],
    file_id: &[u8; FILE_ID_LEN],
    header_bytes: &[u8; HEADER_LEN],
) -> Result<()> {
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut out_buf: Vec<u8> = Vec::with_capacity(NONCE_LEN + CHUNK_SIZE + 16);
    // AAD = HEADER (64B, invariant) || chunk_idx (8B) || is_last_chunk (1B).
    // Pre-fill the invariant header portion; only patch the trailing 9 bytes
    // per chunk.
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
/// Compression is handled internally — if the header indicates a compressed
/// payload, a Zstd decoder is inserted between the chunk loop and `writer`
/// automatically.
fn decrypt_body(
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

/// Compute a repo-relative cache key from a file path.
///
/// `list_files` already produces repo-relative paths, so the common case
/// (relative input) avoids the absolutize+diff round-trip and is reused
/// directly. Absolute inputs (e.g. user-supplied) are diffed against
/// `repo_path`. The result is raw OS-encoded bytes with `b'\\'` replaced by
/// `b'/'` for cross-platform consistency.
fn cache_key(file_path: &Path, repo_path: &Path) -> Vec<u8> {
    let relative = if file_path.is_absolute() {
        diff_paths(file_path, repo_path).unwrap_or_else(|| file_path.to_path_buf())
    } else {
        file_path.to_path_buf()
    };
    let mut bytes = relative.into_os_string().into_encoded_bytes();
    for b in &mut bytes {
        if *b == b'\\' {
            *b = b'/';
        }
    }
    bytes
}

// --- Key Derivation Cache (thundering-herd safe) ---

/// Thread-safe key derivation cache with thundering-herd protection.
///
/// Uses `Arc<OnceLock>` per salt so that when multiple threads encounter the
/// same salt simultaneously (e.g. new files sharing a `batch_salt`), only ONE
/// thread performs the expensive Argon2 computation; all others block on the
/// `OnceLock` and then clone the result.
///
/// The `Arc` allows cloning the handle out of the `DashMap` guard, releasing
/// the internal shard lock before the Argon2 computation starts. This prevents
/// contention on other keys sharing the same shard.
type KeyCache = DashMap<[u8; SALT_LEN], Arc<OnceLock<Result<Zeroizing<[u8; 32]>, String>>>>;

/// Retrieve or derive a key for the given salt, with thundering-herd
/// protection.
///
/// If the key has already been computed, returns a clone immediately.
/// If multiple threads arrive simultaneously for the same salt, only one
/// performs the Argon2 computation; the others block and then clone the result.
fn get_or_derive_key(
    key_cache: &KeyCache,
    master_key: &[u8],
    salt: &[u8; SALT_LEN],
) -> Result<Zeroizing<[u8; 32]>> {
    // Atomically insert a placeholder OnceLock if this salt is new.
    // We clone the Arc so that the DashMap shard lock is released before
    // the potentially slow Argon2 computation, preventing contention on
    // other keys in the same shard.
    let lock = {
        let guard = key_cache
            .entry(*salt)
            .or_insert_with(|| Arc::new(OnceLock::new()));
        Arc::clone(&*guard)
    };

    // Only the first thread to reach get_or_init runs the closure;
    // all others block until the result is available.
    match lock.get_or_init(|| derive_key(master_key, salt).map_err(|e| e.to_string())) {
        Ok(key) => Ok(key.clone()),
        Err(msg) => Err(Error::Argon2(msg.clone())),
    }
}

// --- Streaming Core ---
//
// The lowest-level primitives: pure `Read → Write` with no filesystem
// dependency. These are the building blocks for all higher-level operations.

/// Encrypt data from `reader` into `writer` using streaming chunked encryption.
///
/// This is the most flexible encryption primitive — it operates on arbitrary
/// `Read`/`Write` streams and has no filesystem dependency. The header is
/// written to `writer` first, followed by the encrypted chunks.
///
/// For file-based operations with atomic writes and metadata preservation,
/// use [`encrypt_file_to`] instead.
///
/// # Note: pre-derived key
///
/// This function takes a **pre-derived** key via [`derive_key`] rather than a
/// master password, allowing callers (e.g. [`encrypt_files_to`]) to run Argon2
/// once and reuse the result across many files. For symmetry with
/// [`decrypt_into`], pair this function with an explicit [`derive_key`] call.
///
/// # Arguments
///
/// * `reader` — Source of plaintext data.
/// * `writer` — Destination for encrypted output.
/// * `derived_key` — Argon2-derived 32-byte key (see [`derive_key`]).
/// * `salt` — 16-byte salt stored in the header and used for key derivation.
/// * `file_id` — Optional 16-byte file identifier for deterministic encryption.
///   If `None`, a random one is generated.
/// * `zstd` — Optional Zstd compression level (1–22). If `None`, no
///   compression.
///
/// # Returns
///
/// The [`FileHeader`] that was written, containing the salt and `file_id` used.
///
/// # Example
///
/// ```no_run
/// use git_simple_encrypt::crypt::{encrypt_into, derive_key};
///
/// let salt = [0u8; 16];
/// let derived = derive_key(b"password", &salt)?;
/// let mut input = std::io::Cursor::new(b"hello".to_vec());
/// let mut output = Vec::new();
/// let header = encrypt_into(&mut input, &mut output, &derived, salt, None, None)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn encrypt_into<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    derived_key: &[u8; 32],
    salt: [u8; SALT_LEN],
    file_id: Option<[u8; FILE_ID_LEN]>,
    zstd: Option<u8>,
) -> Result<FileHeader> {
    let file_id = file_id.unwrap_or_else(FileHeader::generate_file_id);
    let header = FileHeader::new(zstd.is_some(), salt, file_id);
    header.write_to(writer)?;

    let (key_enc, key_mac) = split_keys(derived_key);
    let cipher = XChaCha20Poly1305::new(key_enc.as_ref().into());

    // Wrap reader in a Zstd encoder when compression is requested. The encoder
    // takes `reader` by mutable reference; both branches call the same
    // `encrypt_chunks` helper.
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
///
/// This is the most flexible decryption primitive — it operates on arbitrary
/// `Read`/`Write` streams and has no filesystem dependency. The 64-byte header
/// is read from `reader` first, then the encrypted chunks are decrypted.
///
/// For file-based operations with atomic writes and the "is encrypted?" check,
/// use [`decrypt_file_to`] instead.
///
/// # Returns
///
/// The parsed [`FileHeader`], containing the salt and `file_id`. Callers that
/// need deterministic re-encryption can cache these values.
///
/// # Errors
///
/// Returns an error if the reader does not contain a valid GITSE header or if
/// decryption fails (wrong password, corrupt data, tampering).
pub fn decrypt_into<R: Read, W: Write>(
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

// --- File-to-File Operations ---
//
// Mid-level wrappers that add: "is encrypted?" checks, atomic temp-file
// writes, metadata preservation, and parent-directory creation.

/// Encrypt `src` into `dst`.
///
/// If `dst` differs from `src`, the source file is left untouched and the
/// encrypted output is written to `dst` (creating parent directories as
/// needed). Metadata (permissions, timestamps) is copied from `src` to `dst`.
///
/// If `src == dst`, the operation is atomic — the source is overwritten only
/// after encryption completes successfully.
///
/// # Returns
///
/// * `Ok(Some(header))` — Encryption succeeded.
/// * `Ok(None)` — `src` was already encrypted; skipped.
pub fn encrypt_file_to(
    src: &Path,
    dst: &Path,
    derived_key: &[u8; 32],
    salt: [u8; SALT_LEN],
    file_id: Option<[u8; FILE_ID_LEN]>,
    zstd: Option<u8>,
) -> Result<Option<FileHeader>> {
    let mut src_file = fs::File::open(src)?;

    // 1. Skip if source is already encrypted.
    let mut header_bytes = [0u8; HEADER_LEN];
    if src_file.read_exact(&mut header_bytes).is_ok()
        && &header_bytes[0..5] == MAGIC
        && is_encrypted_version(header_bytes[5])
    {
        warn!("Source file already encrypted, skipping: {}", src.display());
        return Ok(None);
    }
    src_file.seek(SeekFrom::Start(0))?;

    debug!("Encrypting {} → {}", src.display(), dst.display());

    // 2. Create a temp file in dst's parent dir for atomic rename.
    let dst_parent = dst.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dst_parent)?;
    let mut temp_file = NamedTempFile::new_in(dst_parent)?;

    // 3. Stream-encrypt from src into temp file.
    let header = encrypt_into(
        &mut src_file,
        &mut temp_file,
        derived_key,
        salt,
        file_id,
        zstd,
    )?;

    // 4. Persist atomically, copying metadata from src.
    drop(src_file);
    persist_temp_file(temp_file, dst, Some(src))?;

    Ok(Some(header))
}

/// Decrypt `src` into `dst`.
///
/// If `dst` differs from `src`, the encrypted source file is left untouched
/// and the decrypted output is written to `dst` (creating parent directories
/// as needed). Metadata (permissions, timestamps) is copied from `src` to
/// `dst`.
///
/// If `src == dst`, the operation is atomic — the source is overwritten only
/// after decryption completes successfully.
///
/// # Returns
///
/// * `Ok(Some(header))` — Decryption succeeded. The header contains the salt
///   and `file_id`, which callers can cache for deterministic re-encryption.
/// * `Ok(None)` — `src` was not encrypted (too small or no valid header);
///   skipped.
///
/// For batch decryption with shared Argon2 key caching, use
/// [`decrypt_files_to`].
pub fn decrypt_file_to(src: &Path, dst: &Path, master_key: &[u8]) -> Result<Option<FileHeader>> {
    let mut src_file = fs::File::open(src)?;

    // 1. Check whether src is encrypted.
    let mut header_bytes = [0u8; HEADER_LEN];
    if src_file.read_exact(&mut header_bytes).is_err() {
        debug!(
            "File too small to be encrypted, skipping: {}",
            src.display()
        );
        return Ok(None);
    }
    if &header_bytes[0..5] != MAGIC || !is_encrypted_version(header_bytes[5]) {
        debug!("File not encrypted (no magic), skipping: {}", src.display());
        return Ok(None);
    }

    debug!("Decrypting {} → {}", src.display(), dst.display());

    let header = *FileHeader::from_bytes(&header_bytes)?;

    // 2. Derive key from master_key + header salt.
    let derived_key = derive_key(master_key, &header.salt)?;

    // 3. Create a temp file in dst's parent dir for atomic rename.
    let dst_parent = dst.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dst_parent)?;
    let mut temp_file = NamedTempFile::new_in(dst_parent)?;

    // 4. Stream-decrypt from src (positioned after header) into temp file.
    let (key_enc, _) = split_keys(&derived_key);
    let cipher = XChaCha20Poly1305::new(key_enc.as_ref().into());
    decrypt_body(&mut src_file, &mut temp_file, &cipher, &header)?;

    // 5. Persist atomically, copying metadata from src.
    drop(src_file);
    persist_temp_file(temp_file, dst, Some(src))?;

    Ok(Some(header))
}

// --- Backward-Compatible Single-File Wrappers ---

/// Encrypt a single file **in place** using streaming chunked encryption.
///
/// This is a convenience wrapper around [`encrypt_file_to`] where `src` and
/// `dst` are the same path.
///
/// Returns `Some(header)` on success, or `None` if the file was already
/// encrypted and skipped.
pub fn encrypt_file(
    path: &Path,
    derived_key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    file_id: Option<[u8; FILE_ID_LEN]>,
    zstd: Option<u8>,
) -> Result<Option<FileHeader>> {
    encrypt_file_to(path, path, derived_key, *salt, file_id, zstd)
}

/// Decrypt a single file **in place** using streaming chunked decryption.
///
/// This is a convenience wrapper around [`decrypt_file_to`] where `src` and
/// `dst` are the same path.
pub fn decrypt_file(path: &Path, master_key: &[u8]) -> Result<()> {
    decrypt_file_to(path, path, master_key).map(|_| ())
}

/// Decrypt a single file **in place**, with a thread-safe Argon2 key cache and
/// an optional salt/`file_id` cache reference for deterministic re-encryption.
///
/// This is the cache-aware variant used by [`decrypt_repo`]. Pass `cache =
/// None` to skip recording `(salt, file_id)`.
///
/// # Thundering-Herd Protection
///
/// When multiple threads decrypt files sharing the same salt (e.g. a batch
/// salt), the `key_cache` ensures Argon2 runs only once per unique salt.
pub fn decrypt_file_with_cache(
    path: &Path,
    key_cache: &KeyCache,
    cache: Option<CacheRef<'_>>,
    master_key: &[u8],
) -> Result<()> {
    let mut file = fs::File::open(path)?;

    // 1. Read and validate header directly (Redundant I/O fixed)
    let mut header_bytes = [0u8; HEADER_LEN];
    if file.read_exact(&mut header_bytes).is_err() {
        debug!(
            "File too small to be encrypted, skipping: {}",
            path.display()
        );
        return Ok(());
    }
    if &header_bytes[0..5] != MAGIC || !is_encrypted_version(header_bytes[5]) {
        debug!(
            "File not encrypted (no magic), skipping: {}",
            path.display()
        );
        return Ok(());
    }

    debug!("Decrypting: {}", path.display());
    let header = *FileHeader::from_bytes(&header_bytes)?;

    // Cache the salt+file_id BEFORE decryption so it is preserved even if
    // decryption fails halfway through.
    if let Some(cache) = cache {
        cache.sender.insert(
            cache.key,
            CachedEntry {
                salt: header.salt,
                file_id: header.file_id,
            },
        );
    }

    // 2. Retrieve or Derive Key (with thundering-herd protection)
    let derived_key = get_or_derive_key(key_cache, master_key, &header.salt)?;

    // 3. Split master key and setup cipher
    let (key_enc, _key_mac) = split_keys(&derived_key);
    let cipher = XChaCha20Poly1305::new(key_enc.as_ref().into());
    let parent_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp_file = NamedTempFile::new_in(parent_dir)?;

    // 4. Stream-decrypt
    decrypt_body(&mut file, &mut temp_file, &cipher, &header)?;
    drop(file);

    // 5. Atomic Write with Metadata Preservation
    persist_temp_file(temp_file, path, Some(path))?;

    Ok(())
}

/// Helper function to read ciphertext chunks, decrypt them, and write to the
/// destination.
///
/// Chunk layout: `[NONCE (24B)] [CIPHERTEXT] [TAG (16B)]`
///
/// `header_bytes` is the raw 64-byte file header, included in every chunk's
/// AAD to bind the ciphertext to the exact header that was present during
/// encryption. Any header tampering will cause Poly1305 authentication failure.
fn decrypt_chunks(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    cipher: &XChaCha20Poly1305,
    header_bytes: &[u8; HEADER_LEN],
) -> Result<()> {
    let mut nonce_buf = [0u8; NONCE_LEN];
    // Zeroizing so the (briefly buffered) ciphertext is scrubbed on return.
    let mut ct_buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE + 16]); // ciphertext + Poly1305 tag
    let ct_len = ct_buffer.len();
    // Pre-fill the invariant header portion of AAD; only the last 9 bytes
    // (chunk_idx + is_last_chunk) change per iteration.
    let mut aad = {
        let mut aad = [0u8; HEADER_LEN + 9];
        aad[..HEADER_LEN].copy_from_slice(header_bytes);
        aad
    };
    let mut last_chunk_was_final = false;
    let mut chunk_idx = 0u64;

    loop {
        // Read the 24-byte nonce from the chunk header.
        match reader.read_exact(&mut nonce_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }

        // Read ciphertext + tag (up to CHUNK_SIZE + 16 bytes).
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

        // Patch only the 9 trailing bytes of AAD per chunk.
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

// --- Batch Operations ---
//
// Parallel multi-file encryption/decryption with caller-supplied destination
// mapping. Each function processes files on a rayon thread pool and shares a
// single Argon2 key cache so that files with the same salt pay the KDF cost
// only once.

/// Summary of a batch encrypt/decrypt run.
#[derive(Debug, Default)]
pub struct BatchSummary {
    /// Total number of source files processed (excluding mapper-rejected
    /// skips).
    pub total: usize,
    /// Files successfully encrypted or decrypted.
    pub succeeded: usize,
    /// Files skipped (already encrypted during encrypt, or not encrypted during
    /// decrypt).
    pub skipped: usize,
    /// Files that failed with an error.
    pub failed: usize,
    /// `(source_path, error)` pairs for every failed file (completion order —
    /// not guaranteed to match source order due to parallel processing).
    pub errors: Vec<(PathBuf, Error)>,
}

impl BatchSummary {
    /// Returns `true` if every file succeeded or was skipped (no failures).
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Decrypt multiple files in parallel, each to a caller-determined destination.
///
/// `mapper` is invoked on every source path and should return the destination
/// path, or `None` to skip that file. Parent directories of each destination
/// are created automatically.
///
/// Files are processed in parallel (rayon). A shared Argon2 key cache ensures
/// that files sharing the same salt pay the KDF cost only once.
///
/// # Mapper errors
///
/// If the mapper returns `None`, the file is silently skipped — there is no
/// way to distinguish "intentional skip" from a mapper logic error. For
/// fallible mapping logic, consider pre-filtering the source list before
/// calling this function.
///
/// # Non-encrypted sources
///
/// Sources that are not GITSE-encrypted are silently skipped (counted in
/// `BatchSummary::skipped`), matching [`decrypt_file_to`] semantics.
///
/// # Example
///
/// ```no_run
/// use git_simple_encrypt::crypt::decrypt_files_to;
/// use std::path::{Path, PathBuf};
///
/// let sources = vec![PathBuf::from("a.enc"), PathBuf::from("b.enc")];
/// let summary = decrypt_files_to(
///     &sources,
///     b"master_password",
///     |src: &Path| Some(PathBuf::from("/tmp/out").join(src.file_name()?)),
/// )?;
/// assert!(summary.is_ok());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn decrypt_files_to<I, P, F>(sources: I, master_key: &[u8], mapper: F) -> Result<BatchSummary>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path> + Sync,
    F: Fn(&Path) -> Option<PathBuf> + Sync,
{
    let sources: Vec<PathBuf> = sources
        .into_iter()
        .map(|p| p.as_ref().to_path_buf())
        .collect();
    let total = sources.len();

    let key_cache: KeyCache = DashMap::new();
    let errors: parking_lot::Mutex<Vec<(PathBuf, Error)>> = parking_lot::Mutex::new(Vec::new());
    let skipped = AtomicUsize::new(0);
    let succeeded = AtomicUsize::new(0);

    sources.par_iter().for_each(|src| {
        let Some(dst) = mapper(src) else { return };

        match decrypt_file_to_with_key_cache(src, &dst, &key_cache, master_key) {
            Ok(Some(_)) => {
                succeeded.fetch_add(1, Ordering::Relaxed);
            }
            Ok(None) => {
                skipped.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                errors.lock().push((src.clone(), e));
            }
        }
    });

    let errors = errors.into_inner();
    let succeeded = succeeded.load(Ordering::Relaxed);
    let skipped = skipped.load(Ordering::Relaxed);
    let failed = errors.len();

    Ok(BatchSummary {
        total,
        succeeded,
        skipped,
        failed,
        errors,
    })
}

/// Encrypt multiple files in parallel, each from a caller-determined source to
/// a caller-determined destination.
///
/// `mapper` is invoked on every source path and should return the destination
/// path, or `None` to skip that file. Parent directories of each destination
/// are created automatically.
///
/// # Mapper errors
///
/// If the mapper returns `None`, the file is silently skipped — there is no
/// way to distinguish "intentional skip" from a mapper logic error. For
/// fallible mapping logic, consider pre-filtering the source list before
/// calling this function.
///
/// A single batch salt is generated and used for all files that don't already
/// have a cached `salt/file_id`. The Argon2 key is derived once and shared
/// across all files, making this efficient for large batches.
///
/// # Already-encrypted sources
///
/// Source files that are already GITSE-encrypted are silently skipped (counted
/// in `BatchSummary::skipped`).
///
/// # Example
///
/// ```no_run
/// use git_simple_encrypt::crypt::encrypt_files_to;
/// use std::path::{Path, PathBuf};
///
/// // Encrypt external files into a repo directory
/// let sources = vec![PathBuf::from("/home/user/secret1.txt"),
///                    PathBuf::from("/home/user/secret2.txt")];
/// let summary = encrypt_files_to(
///     &sources,
///     b"master_password",
///     |src: &Path| Some(PathBuf::from("repo/secrets").join(src.file_name()?)),
///     None, // no zstd compression
/// )?;
/// assert!(summary.is_ok());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn encrypt_files_to<I, P, F>(
    sources: I,
    master_key: &[u8],
    mapper: F,
    zstd: Option<u8>,
) -> Result<BatchSummary>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path> + Sync,
    F: Fn(&Path) -> Option<PathBuf> + Sync,
{
    let sources: Vec<PathBuf> = sources
        .into_iter()
        .map(|p| p.as_ref().to_path_buf())
        .collect();
    let total = sources.len();

    // Single batch salt + single Argon2 derivation shared across all files.
    let mut batch_salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut batch_salt);
    let derived_key = derive_key(master_key, &batch_salt)?;

    let errors: parking_lot::Mutex<Vec<(PathBuf, Error)>> = parking_lot::Mutex::new(Vec::new());
    let skipped = AtomicUsize::new(0);
    let succeeded = AtomicUsize::new(0);

    sources.par_iter().for_each(|src| {
        let Some(dst) = mapper(src) else { return };

        match encrypt_file_to(src, &dst, &derived_key, batch_salt, None, zstd) {
            Ok(Some(_)) => {
                succeeded.fetch_add(1, Ordering::Relaxed);
            }
            Ok(None) => {
                skipped.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                errors.lock().push((src.clone(), e));
            }
        }
    });

    let errors = errors.into_inner();
    let succeeded = succeeded.load(Ordering::Relaxed);
    let skipped = skipped.load(Ordering::Relaxed);
    let failed = errors.len();

    Ok(BatchSummary {
        total,
        succeeded,
        skipped,
        failed,
        errors,
    })
}

/// Internal: decrypt `src` → `dst` using a shared Argon2 key cache so that
/// files with identical salts in a batch pay the KDF cost only once.
fn decrypt_file_to_with_key_cache(
    src: &Path,
    dst: &Path,
    key_cache: &KeyCache,
    master_key: &[u8],
) -> Result<Option<FileHeader>> {
    let mut src_file = fs::File::open(src)?;

    let mut header_bytes = [0u8; HEADER_LEN];
    if src_file.read_exact(&mut header_bytes).is_err() {
        debug!(
            "File too small to be encrypted, skipping: {}",
            src.display()
        );
        return Ok(None);
    }
    if &header_bytes[0..5] != MAGIC || !is_encrypted_version(header_bytes[5]) {
        debug!("File not encrypted (no magic), skipping: {}", src.display());
        return Ok(None);
    }

    debug!("Decrypting {} → {}", src.display(), dst.display());

    let header = *FileHeader::from_bytes(&header_bytes)?;
    let derived_key = get_or_derive_key(key_cache, master_key, &header.salt)?;

    let dst_parent = dst.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dst_parent)?;
    let mut temp_file = NamedTempFile::new_in(dst_parent)?;

    let (key_enc, _) = split_keys(&derived_key);
    let cipher = XChaCha20Poly1305::new(key_enc.as_ref().into());
    decrypt_body(&mut src_file, &mut temp_file, &cipher, &header)?;

    drop(src_file);
    persist_temp_file(temp_file, dst, Some(src))?;

    Ok(Some(header))
}

// --- Repo Integration ---

/// Encrypt given files in the repo. If no paths are given, encrypt all files
/// in the repo's crypt list.
///
/// # Deterministic Re-encryption
///
/// Loads the `salt+file_id` cache (populated by a previous decrypt) via mmap +
/// rkyv zero-copy and reuses cached values so that decrypt→encrypt on
/// unchanged content produces byte-identical ciphertext. Files not in the
/// cache share a single new batch salt to minimise Argon2 overhead.
///
/// The cache is **read-only** during encryption; only the decrypt path
/// writes to the cache.
pub fn encrypt_repo(repo: &Repo, paths: &[PathBuf]) -> Result<()> {
    let key = repo.get_key()?;
    if key.is_empty() {
        return Err(Error::EmptyKey);
    }

    let target_files = resolve_target_files(paths, &repo.conf.crypt_list, repo.path());
    if target_files.is_empty() {
        return Err(Error::NoFile("encrypt"));
    }

    // Pre-operation report
    print_pre_report("Encrypting", &target_files, repo.path());

    // Read-only cache: mmap + rkyv zero-copy. No write during encryption.
    let reader = salt_cache::SaltCacheReader::load(repo.path());

    let key_cache: KeyCache = DashMap::new();

    // Generate a single batch salt for files that have no cache entry.
    let mut batch_salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut batch_salt);

    let pb = Progress::new(target_files.len(), "Encrypt");
    let skipped = AtomicUsize::new(0);
    let failed = AtomicUsize::new(0);

    let result = {
        let errors: parking_lot::Mutex<Vec<Error>> = parking_lot::Mutex::new(Vec::new());
        target_files.par_iter().for_each(|f| {
            let relative_key = cache_key(f, repo.path());
            let (salt, cached_file_id) = reader
                .get(&relative_key)
                .map_or((batch_salt, None), |entry| {
                    (entry.salt, Some(entry.file_id))
                });

            // Derive key — thundering-herd safe: only one thread per salt runs Argon2.
            let derived_key = match get_or_derive_key(&key_cache, key.as_bytes(), &salt) {
                Ok(k) => k,
                Err(e) => {
                    failed.fetch_add(1, Ordering::Relaxed);
                    errors.lock().push(e);
                    pb.inc(1);
                    return;
                }
            };

            let r = encrypt_file(
                f,
                &derived_key,
                &salt,
                cached_file_id,
                repo.conf.use_zstd.then_some(repo.conf.zstd_level),
            )
            .map_err(|e| Error::Other(format!("Failed to encrypt {}: {e}", f.display())));

            match r {
                Ok(Some(_)) => {}
                Ok(None) => {
                    skipped.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    failed.fetch_add(1, Ordering::Relaxed);
                    errors.lock().push(e);
                }
            }

            pb.inc(1);
        });
        errors.into_inner()
    };

    pb.finish_and_clear();

    print_post_report(
        "Encrypt",
        target_files.len(),
        skipped.load(Ordering::Relaxed),
        failed.load(Ordering::Relaxed),
    );

    if let Some(first) = result.into_iter().next() {
        return Err(first);
    }

    Ok(())
}

/// Decrypt given files in the repo. If no paths are given, decrypt all files
/// in the repo's crypt list.
///
/// The `salt+file_id` of each successfully parsed encrypted file is captured
/// via an mpsc channel so that a subsequent encrypt can reproduce identical
/// ciphertext.
pub fn decrypt_repo(repo: &Repo, paths: &[PathBuf]) -> Result<()> {
    let key = repo.get_key()?;
    if key.is_empty() {
        return Err(Error::EmptyKey);
    }

    let target_files = resolve_target_files(paths, &repo.conf.crypt_list, repo.path());
    if target_files.is_empty() {
        return Err(Error::NoFile("decrypt"));
    }

    // Pre-operation report
    print_pre_report("Decrypting", &target_files, repo.path());

    let key_cache: KeyCache = DashMap::new();

    // Write-only: mpsc channel collects salt/file_id from rayon threads.
    let (sender, saver) = salt_cache::create_writer(repo.path());

    let pb = Progress::new(target_files.len(), "Decrypt");
    let skipped = AtomicUsize::new(0);
    let failed = AtomicUsize::new(0);

    let result = {
        let errors: parking_lot::Mutex<Vec<Error>> = parking_lot::Mutex::new(Vec::new());
        target_files.par_iter().for_each(|f| {
            match is_file_encrypted(f) {
                Ok(true) => {}
                Ok(false) => {
                    skipped.fetch_add(1, Ordering::Relaxed);
                    pb.inc(1);
                    return;
                }
                Err(e) => {
                    failed.fetch_add(1, Ordering::Relaxed);
                    errors.lock().push(e);
                    pb.inc(1);
                    return;
                }
            }

            let relative_key = cache_key(f, repo.path());

            let r = decrypt_file_with_cache(
                f,
                &key_cache,
                Some(CacheRef {
                    sender: &sender,
                    key: &relative_key,
                }),
                key.as_bytes(),
            )
            .map_err(|e| Error::Other(format!("Failed to decrypt {}: {e}", f.display())));

            if let Err(e) = r {
                failed.fetch_add(1, Ordering::Relaxed);
                errors.lock().push(e);
            }

            pb.inc(1);
        });
        errors.into_inner()
    };

    // Drop sender to close the channel, then persist the cache.
    drop(sender);
    saver.save();

    pb.finish_and_clear();

    print_post_report(
        "Decrypt",
        target_files.len(),
        skipped.load(Ordering::Relaxed),
        failed.load(Ordering::Relaxed),
    );

    if let Some(first) = result.into_iter().next() {
        return Err(first);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use tempfile::{NamedTempFile, TempPath};

    use super::*;

    // --- Helper Functions ---

    fn get_test_key_and_salt() -> ([u8; 32], [u8; SALT_LEN]) {
        let password = b"super_secret_password";
        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        let derived = derive_key(password, &salt).unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(&*derived);
        (key, salt)
    }

    fn create_temp_file(content: &[u8]) -> TempPath {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content).unwrap();
        file.flush().unwrap();
        file.into_temp_path()
    }

    // --- Tests ---

    #[test]
    fn test_header_serialization() {
        let salt = [0xAB; SALT_LEN];
        let file_id = FileHeader::generate_file_id();
        let header = FileHeader::new(true, salt, file_id);

        // Write to buffer
        let mut buf = Vec::new();
        header.write_to(&mut buf).unwrap();
        assert_eq!(buf.len(), HEADER_LEN);

        // Roundtrip: bytes → from_bytes (zero-copy)
        let raw: &[u8; HEADER_LEN] = buf.as_slice().try_into().unwrap();
        let decoded = FileHeader::from_bytes(raw).unwrap();

        assert_eq!(decoded.magic, *MAGIC);
        assert_eq!(decoded.version, VERSION);
        assert_eq!(decoded.flags, FLAG_COMPRESSED);
        assert_eq!(decoded.enc_algo, ENC_ALGO);
        assert_eq!(decoded.salt, salt);
        assert_eq!(decoded.file_id, header.file_id);
        assert_eq!(decoded.reserved, [0u8; RESERVED_LEN]);
        assert!(decoded.is_compressed());
    }

    #[test]
    fn test_nonce_derivation_deterministic() {
        let key_mac = [0x42u8; 32];
        let file_id = [0x99u8; FILE_ID_LEN];
        let plaintext = b"hello world";

        // Same inputs → same nonce (deterministic).
        let nonce0_a = derive_nonce(&key_mac, &file_id, plaintext, 0);
        let nonce0_b = derive_nonce(&key_mac, &file_id, plaintext, 0);
        assert_eq!(nonce0_a, nonce0_b);

        // Different chunk index → different nonce.
        let nonce1 = derive_nonce(&key_mac, &file_id, plaintext, 1);
        assert_ne!(nonce0_a, nonce1);

        // Different plaintext → different nonce.
        let other_plaintext = b"hello world!";
        let nonce_other = derive_nonce(&key_mac, &file_id, other_plaintext, 0);
        assert_ne!(nonce0_a, nonce_other);

        // Different key_mac → different nonce.
        let key_mac2 = [0x43u8; 32];
        let nonce_key2 = derive_nonce(&key_mac2, &file_id, plaintext, 0);
        assert_ne!(nonce0_a, nonce_key2);

        // Different file_id → different nonce (cross-file uniqueness).
        let file_id2 = [0xAAu8; FILE_ID_LEN];
        let nonce_file2 = derive_nonce(&key_mac, &file_id2, plaintext, 0);
        assert_ne!(nonce0_a, nonce_file2);

        // Empty plaintext should still produce a valid nonce.
        let nonce_empty = derive_nonce(&key_mac, &file_id, b"", 0);
        assert_ne!(nonce_empty, [0u8; NONCE_LEN]);
    }

    #[test]
    fn test_encrypt_decrypt_basic_no_compression() {
        let plaintext = b"Hello, World! This is a test without compression.";
        let path = create_temp_file(plaintext);

        let (key, salt) = get_test_key_and_salt();
        let master_key = b"super_secret_password";

        // Encrypt
        encrypt_file(&path, &key, &salt, None, None).unwrap();

        // Verify it's encrypted
        let mut encrypted_content = Vec::new();
        fs::File::open(&path)
            .unwrap()
            .read_to_end(&mut encrypted_content)
            .unwrap();
        assert_ne!(encrypted_content, plaintext);
        assert_eq!(&encrypted_content[0..5], MAGIC);
        assert_eq!(encrypted_content[5], VERSION);

        // Decrypt
        decrypt_file(&path, master_key).unwrap();

        // Verify plaintext
        let mut decrypted_content = Vec::new();
        fs::File::open(path)
            .unwrap()
            .read_to_end(&mut decrypted_content)
            .unwrap();
        assert_eq!(decrypted_content, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_compression() {
        // Highly compressible data
        let plaintext = b"A".repeat(10000);
        let path = create_temp_file(&plaintext);

        let (key, salt) = get_test_key_and_salt();
        let master_key = b"super_secret_password";

        // Encrypt with Zstd level 3
        encrypt_file(&path, &key, &salt, None, Some(3)).unwrap();

        // Verify it's encrypted and compressed (size should be much smaller than 10000
        // + header)
        let encrypted_meta = fs::metadata(&path).unwrap();
        assert!(encrypted_meta.len() < 5000);

        // Decrypt
        decrypt_file(&path, master_key).unwrap();

        // Verify plaintext
        let mut decrypted_content = Vec::new();
        fs::File::open(path)
            .unwrap()
            .read_to_end(&mut decrypted_content)
            .unwrap();
        assert_eq!(decrypted_content, plaintext);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    fn test_chunked_encryption_large_file() {
        // Create a file larger than CHUNK_SIZE (64KB) to test the streaming loop
        let plaintext = {
            let mut data = Vec::with_capacity(100_000);
            for i in 0..100_000 {
                data.push((i % 256) as u8);
            }
            data
        };

        let path = create_temp_file(&plaintext);

        let (key, salt) = get_test_key_and_salt();
        let master_key = b"super_secret_password";

        // Encrypt
        encrypt_file(&path, &key, &salt, None, None).unwrap();

        // Decrypt
        decrypt_file(&path, master_key).unwrap();

        // Verify plaintext
        let mut decrypted_content = Vec::new();
        fs::File::open(path)
            .unwrap()
            .read_to_end(&mut decrypted_content)
            .unwrap();
        assert_eq!(decrypted_content, plaintext);
    }

    #[test]
    fn test_tamper_resistance() {
        let plaintext = b"Sensitive data that should not be tampered with.";
        let path = create_temp_file(plaintext);

        let (key, salt) = get_test_key_and_salt();
        let master_key = b"super_secret_password";

        // Encrypt
        encrypt_file(&path, &key, &salt, None, None).unwrap();

        // Tamper with the ciphertext (modify a byte after the 64-byte header)
        let mut encrypted_content = Vec::new();
        let mut f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        f.read_to_end(&mut encrypted_content).unwrap();

        // Flip a bit in the ciphertext
        encrypted_content[HEADER_LEN + 5] ^= 0xFF;

        f.seek(std::io::SeekFrom::Start(0)).unwrap();
        f.write_all(&encrypted_content).unwrap();
        drop(f);

        // Attempt to decrypt, should fail due to Poly1305 MAC mismatch
        let result = decrypt_file(&path, master_key);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .to_lowercase()
                .contains("decryption failed")
        );
    }

    #[test]
    fn test_header_tamper_detected() {
        let plaintext = b"Test data with header integrity check.";
        let path = create_temp_file(plaintext);

        let (key, salt) = get_test_key_and_salt();
        let master_key = b"super_secret_password";

        // Encrypt
        encrypt_file(&path, &key, &salt, None, None).unwrap();

        // Tamper with the header flags byte (flip the compressed bit at byte 6)
        let mut encrypted_content = Vec::new();
        let mut f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        f.read_to_end(&mut encrypted_content).unwrap();

        encrypted_content[6] ^= FLAG_COMPRESSED;

        f.seek(std::io::SeekFrom::Start(0)).unwrap();
        f.write_all(&encrypted_content).unwrap();
        drop(f);

        // Attempt to decrypt — should fail because header tampering changes
        // the AAD, causing Poly1305 authentication failure.
        let result = decrypt_file(&path, master_key);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .to_lowercase()
                .contains("decryption failed")
        );
    }

    #[test]
    fn test_deterministic_encrypt_with_fixed_salt_file_id() {
        let plaintext = b"Deterministic encryption test data.";

        let password = b"test_password";
        let salt = [0x42; SALT_LEN];
        let file_id = [0x13; FILE_ID_LEN];
        let derived = derive_key(password, &salt).unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(&*derived);

        // Encrypt twice with the same salt+file_id → identical ciphertext
        let path1 = create_temp_file(plaintext);
        let path2 = create_temp_file(plaintext);

        encrypt_file(&path1, &key, &salt, Some(file_id), None).unwrap();
        encrypt_file(&path2, &key, &salt, Some(file_id), None).unwrap();

        let ct1 = fs::read(&path1).unwrap();
        let ct2 = fs::read(&path2).unwrap();
        assert_eq!(
            ct1, ct2,
            "Same plaintext + same salt+file_id must produce identical ciphertext"
        );

        // And both should decrypt correctly
        decrypt_file(&path1, password).unwrap();
        assert_eq!(fs::read(&path1).unwrap(), plaintext);
    }

    #[test]
    fn test_deterministic_encrypt_multi_chunk() {
        // Multi-chunk file: test determinism across chunk boundaries.
        #[allow(clippy::cast_possible_truncation)]
        let plaintext = {
            let mut data = Vec::with_capacity(CHUNK_SIZE * 2 + 1000);
            for i in 0..(CHUNK_SIZE * 2 + 1000) {
                data.push(i as u8);
            }
            data
        };

        let password = b"test_password";
        let salt = [0x42; SALT_LEN];
        let file_id = [0x13; FILE_ID_LEN];
        let derived = derive_key(password, &salt).unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(&*derived);

        let path1 = create_temp_file(&plaintext);
        let path2 = create_temp_file(&plaintext);

        encrypt_file(&path1, &key, &salt, Some(file_id), None).unwrap();
        encrypt_file(&path2, &key, &salt, Some(file_id), None).unwrap();

        let ct1 = fs::read(&path1).unwrap();
        let ct2 = fs::read(&path2).unwrap();
        assert_eq!(
            ct1, ct2,
            "Same multi-chunk plaintext + same salt+file_id must produce identical ciphertext"
        );

        // Decrypt and verify
        decrypt_file(&path1, password).unwrap();
        assert_eq!(fs::read(&path1).unwrap(), plaintext);
    }

    #[test]
    fn test_different_file_id_produces_different_ciphertext() {
        // Verify that the same plaintext encrypted with different File_IDs
        // produces different ciphertext (cross-file uniqueness).
        let plaintext = b"Same content, different file.";

        let password = b"test_password";
        let salt = [0x42; SALT_LEN];
        let derived = derive_key(password, &salt).unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(&*derived);

        let path1 = create_temp_file(plaintext);
        let path2 = create_temp_file(plaintext);

        let file_id1 = [0x01; FILE_ID_LEN];
        let file_id2 = [0x02; FILE_ID_LEN];

        encrypt_file(&path1, &key, &salt, Some(file_id1), None).unwrap();
        encrypt_file(&path2, &key, &salt, Some(file_id2), None).unwrap();

        let ct1 = fs::read(&path1).unwrap();
        let ct2 = fs::read(&path2).unwrap();
        assert_ne!(
            ct1, ct2,
            "Same plaintext with different File_IDs must produce different ciphertext"
        );

        // Both should decrypt correctly
        decrypt_file(&path1, password).unwrap();
        assert_eq!(fs::read(&path1).unwrap(), plaintext);
        decrypt_file(&path2, password).unwrap();
        assert_eq!(fs::read(&path2).unwrap(), plaintext);
    }

    #[cfg(unix)]
    #[test]
    fn test_metadata_preservation() {
        use std::os::unix::fs::PermissionsExt;

        let plaintext = b"Executable script content";
        let file = create_temp_file(plaintext);
        let path = file.path();

        // Set permissions to 0o755 (rwxr-xr-x)
        let mut perms = fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).unwrap();

        let (key, salt) = get_test_key_and_salt();
        let master_key = b"super_secret_password";

        // Encrypt
        encrypt_file(path, &key, &salt, None, None).unwrap();

        // Check permissions after encryption
        let encrypted_perms = fs::metadata(path).unwrap().permissions();
        assert_eq!(encrypted_perms.mode() & 0o777, 0o755);

        // Decrypt
        let key_cache: KeyCache = DashMap::new();
        decrypt_file_with_cache(path, &key_cache, None, master_key).unwrap();

        // Check permissions after decryption
        let decrypted_perms = fs::metadata(path).unwrap().permissions();
        assert_eq!(decrypted_perms.mode() & 0o777, 0o755);
    }

    #[test]
    fn test_empty_file_roundtrip() {
        // Edge case: 0-byte plaintext. The encrypt loop should produce a
        // single last (empty) chunk; decrypt should yield back 0 bytes.
        let plaintext = b"";
        let path = create_temp_file(plaintext);

        let (key, salt) = get_test_key_and_salt();
        let master_key = b"super_secret_password";

        encrypt_file(&path, &key, &salt, None, None).unwrap();

        // Header + one chunk (24B nonce + 16B tag of empty plaintext).
        let enc = fs::read(&path).unwrap();
        assert_eq!(enc.len(), HEADER_LEN + NONCE_LEN + 16);

        decrypt_file(&path, master_key).unwrap();
        assert_eq!(fs::read(&path).unwrap(), plaintext);
    }

    #[test]
    fn test_wrong_password_decrypt_fails() {
        let plaintext = b"data encrypted under one password";
        let path = create_temp_file(plaintext);

        let (key, salt) = get_test_key_and_salt();
        encrypt_file(&path, &key, &salt, None, None).unwrap();

        // Decrypt with a different password: AEAD authentication must fail.
        let result = decrypt_file(&path, b"a_completely_different_password");
        assert!(matches!(result, Err(Error::DecryptFailed(_))));

        // And the original file must be untouched (atomic writeback did not run).
        let bytes = fs::read(&path).unwrap();
        assert_eq!(&bytes[..MAGIC.len()], MAGIC);
    }

    #[test]
    fn test_truncated_ciphertext_after_nonce() {
        // Header + 24-byte nonce + 0 bytes of ciphertext -> TruncatedChunk.
        let plaintext = b"abc";
        let path = create_temp_file(plaintext);
        let (key, salt) = get_test_key_and_salt();
        encrypt_file(&path, &key, &salt, None, None).unwrap();

        // Truncate the file to keep only header + nonce (drop ct + tag).
        let trunc_len = HEADER_LEN + NONCE_LEN;
        let f = fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len(trunc_len as u64).unwrap();
        drop(f);

        let result = decrypt_file(&path, b"super_secret_password");
        assert!(matches!(result, Err(Error::TruncatedChunk)));
    }

    #[test]
    fn test_truncated_before_first_nonce() {
        // File smaller than HEADER_LEN: decrypt_file_with_cache should treat
        // it as "not encrypted" and return Ok without touching it.
        let path = create_temp_file(b"tiny");
        let key_cache: KeyCache = DashMap::new();
        let res = decrypt_file_with_cache(&path, &key_cache, None, b"any");
        assert!(res.is_ok());
        // Plaintext unchanged.
        assert_eq!(fs::read(&path).unwrap(), b"tiny");
    }

    // --- Streaming Core Tests (encrypt_into / decrypt_into) ---

    #[test]
    fn test_stream_encrypt_decrypt_roundtrip() {
        let plaintext = b"streaming core roundtrip test data";
        let (key, salt) = get_test_key_and_salt();
        let master_key = b"super_secret_password";

        // Encrypt into a Vec<u8>
        let mut reader = std::io::Cursor::new(plaintext.to_vec());
        let mut ciphertext = Vec::new();
        let header = encrypt_into(&mut reader, &mut ciphertext, &key, salt, None, None).unwrap();

        // Verify header was written
        assert_eq!(&ciphertext[0..5], MAGIC);
        assert_eq!(ciphertext[5], VERSION);

        // Decrypt back
        let mut enc_reader = std::io::Cursor::new(ciphertext.clone());
        let mut decrypted = Vec::new();
        let dec_header = decrypt_into(&mut enc_reader, &mut decrypted, master_key).unwrap();

        assert_eq!(decrypted, plaintext);
        assert_eq!(header.salt, dec_header.salt);
        assert_eq!(header.file_id, dec_header.file_id);
    }

    #[test]
    fn test_stream_encrypt_with_compression() {
        let plaintext = b"X".repeat(50_000); // highly compressible
        let (key, salt) = get_test_key_and_salt();
        let master_key = b"super_secret_password";

        let mut reader = std::io::Cursor::new(plaintext.clone());
        let mut ciphertext = Vec::new();
        encrypt_into(&mut reader, &mut ciphertext, &key, salt, None, Some(3)).unwrap();

        // Compressed + encrypted should be much smaller than original.
        assert!(ciphertext.len() < 5_000);

        let mut enc_reader = std::io::Cursor::new(ciphertext);
        let mut decrypted = Vec::new();
        decrypt_into(&mut enc_reader, &mut decrypted, master_key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_stream_encrypt_deterministic_with_fixed_file_id() {
        let plaintext = b"deterministic stream test";
        let (key, salt) = get_test_key_and_salt();
        let file_id = [0x42; FILE_ID_LEN];

        let mut r1 = std::io::Cursor::new(plaintext.to_vec());
        let mut c1 = Vec::new();
        encrypt_into(&mut r1, &mut c1, &key, salt, Some(file_id), None).unwrap();

        let mut r2 = std::io::Cursor::new(plaintext.to_vec());
        let mut c2 = Vec::new();
        encrypt_into(&mut r2, &mut c2, &key, salt, Some(file_id), None).unwrap();

        assert_eq!(c1, c2, "Same plaintext + salt + file_id must be identical");
    }

    // --- File-to-File Tests (encrypt_file_to / decrypt_file_to) ---

    #[test]
    fn test_encrypt_file_to_different_destination() {
        let plaintext = b"file-to-file test data";
        let src = create_temp_file(plaintext);
        let dst_dir = tempfile::TempDir::new().unwrap();
        let dst = dst_dir.path().join("output.enc");

        let (key, salt) = get_test_key_and_salt();
        let master_key = b"super_secret_password";

        // Encrypt src → dst
        let header = encrypt_file_to(&src, &dst, &key, salt, None, None).unwrap();
        assert!(header.is_some());

        // Source must be unchanged
        assert_eq!(fs::read(&src).unwrap(), plaintext);

        // Destination must be encrypted
        let enc = fs::read(&dst).unwrap();
        assert_eq!(&enc[0..5], MAGIC);

        // Decrypt dst → src2 (a new file)
        let dst2 = dst_dir.path().join("output.dec");
        let result = decrypt_file_to(&dst, &dst2, master_key).unwrap();
        assert!(result.is_some());

        assert_eq!(fs::read(&dst2).unwrap(), plaintext);
    }

    #[test]
    fn test_encrypt_file_to_creates_parent_dirs() {
        let plaintext = b"nested dir test";
        let src = create_temp_file(plaintext);
        let dst_dir = tempfile::TempDir::new().unwrap();
        let dst = dst_dir.path().join("a/b/c/output.enc");

        let (key, salt) = get_test_key_and_salt();
        encrypt_file_to(&src, &dst, &key, salt, None, None).unwrap();

        assert!(dst.exists());
        assert_eq!(&fs::read(&dst).unwrap()[0..5], MAGIC);
    }

    #[test]
    fn test_decrypt_file_to_skips_non_encrypted() {
        let src = create_temp_file(b"just plaintext, no encryption");
        let dst_dir = tempfile::TempDir::new().unwrap();
        let dst = dst_dir.path().join("out.txt");

        let result = decrypt_file_to(&src, &dst, b"any_key").unwrap();
        assert!(result.is_none(), "Should skip non-encrypted file");
        assert!(!dst.exists(), "Destination should not be created");
    }

    #[test]
    fn test_encrypt_file_to_skips_already_encrypted() {
        let plaintext = b"already encrypted source";
        let (key, salt) = get_test_key_and_salt();

        // First, encrypt the source in-place.
        let src = create_temp_file(plaintext);
        encrypt_file(&src, &key, &salt, None, None).unwrap();
        assert_eq!(&fs::read(&src).unwrap()[0..5], MAGIC);

        // Now try encrypt_file_to from the already-encrypted source.
        let dst_dir = tempfile::TempDir::new().unwrap();
        let dst = dst_dir.path().join("out2.enc");
        let result = encrypt_file_to(&src, &dst, &key, salt, None, None).unwrap();
        assert!(result.is_none(), "Should skip already-encrypted source");
        assert!(!dst.exists());
    }

    #[test]
    fn test_encrypt_file_to_in_place_matches_encrypt_file() {
        // encrypt_file(path, ...) == encrypt_file_to(path, path, ...)
        let plaintext = b"in-place compatibility test";
        let (key, salt) = get_test_key_and_salt();

        let p1 = create_temp_file(plaintext);
        encrypt_file(&p1, &key, &salt, Some([0xAA; FILE_ID_LEN]), None).unwrap();

        let p2 = create_temp_file(plaintext);
        encrypt_file_to(&p2, &p2, &key, salt, Some([0xAA; FILE_ID_LEN]), None).unwrap();

        assert_eq!(fs::read(&p1).unwrap(), fs::read(&p2).unwrap());
    }

    // --- Batch API Tests ---

    #[test]
    fn test_decrypt_files_to_batch() {
        let master_key = b"batch_password";
        let (key, salt) = {
            let password = master_key;
            let mut s = [0u8; SALT_LEN];
            rand::rng().fill_bytes(&mut s);
            let derived = derive_key(password, &s).unwrap();
            let mut k = [0u8; 32];
            k.copy_from_slice(&*derived);
            (k, s)
        };

        // Create 3 encrypted source files. Keep TempPath alive so the files
        // aren't auto-deleted before decryption runs.
        let temp_paths: Vec<TempPath> = (0..3)
            .map(|i| {
                let path = create_temp_file(format!("batch item {i}").as_bytes());
                encrypt_file(&path, &key, &salt, None, None).unwrap();
                path
            })
            .collect();
        let sources: Vec<PathBuf> = temp_paths.iter().map(PathBuf::from).collect();

        // Decrypt all to a temp directory.
        let out_dir = tempfile::TempDir::new().unwrap();
        let summary = decrypt_files_to(&sources, master_key, |src: &Path| {
            Some(out_dir.path().join(src.file_name().unwrap()))
        })
        .unwrap();

        assert_eq!(summary.total, 3);
        assert_eq!(summary.succeeded, 3);
        assert_eq!(summary.skipped, 0);
        assert_eq!(summary.failed, 0);
        assert!(summary.is_ok());

        // Verify decrypted content
        for (i, src) in sources.iter().enumerate() {
            let dec_path = out_dir.path().join(src.file_name().unwrap());
            assert_eq!(
                fs::read(&dec_path).unwrap(),
                format!("batch item {i}").as_bytes()
            );
        }
    }

    #[test]
    fn test_decrypt_files_to_skips_non_encrypted() {
        let temp_paths: Vec<TempPath> = (0..3)
            .map(|i| create_temp_file(format!("plaintext {i}").as_bytes()))
            .collect();
        let sources: Vec<PathBuf> = temp_paths.iter().map(PathBuf::from).collect();

        let out_dir = tempfile::TempDir::new().unwrap();
        let summary = decrypt_files_to(&sources, b"any", |src: &Path| {
            Some(out_dir.path().join(src.file_name().unwrap()))
        })
        .unwrap();

        assert_eq!(summary.total, 3);
        assert_eq!(summary.succeeded, 0);
        assert_eq!(summary.skipped, 3);
        assert_eq!(summary.failed, 0);
    }

    #[test]
    fn test_decrypt_files_to_mapper_skip() {
        let master_key = b"batch_password";
        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        let derived = derive_key(master_key, &salt).unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(&*derived);

        let temp_paths: Vec<TempPath> = (0..3)
            .map(|i| {
                let path = create_temp_file(format!("item {i}").as_bytes());
                encrypt_file(&path, &key, &salt, None, None).unwrap();
                path
            })
            .collect();
        let sources: Vec<PathBuf> = temp_paths.iter().map(PathBuf::from).collect();

        let out_dir = tempfile::TempDir::new().unwrap();
        let skip_path = sources[1].clone();
        let summary = decrypt_files_to(&sources, master_key, |src: &Path| {
            // Skip the second file (index 1).
            if src == skip_path.as_path() {
                None
            } else {
                Some(out_dir.path().join(src.file_name().unwrap()))
            }
        })
        .unwrap();

        assert_eq!(summary.succeeded, 2);
        assert!(summary.is_ok());
    }

    #[test]
    fn test_encrypt_files_to_batch() {
        let master_key = b"batch_encrypt_password";

        // Create 3 plaintext source files outside the "repo".
        let temp_paths: Vec<TempPath> = (0..3)
            .map(|i| create_temp_file(format!("source item {i}").as_bytes()))
            .collect();
        let sources: Vec<PathBuf> = temp_paths.iter().map(PathBuf::from).collect();

        let out_dir = tempfile::TempDir::new().unwrap();
        let summary = encrypt_files_to(
            &sources,
            master_key,
            |src: &Path| Some(out_dir.path().join(src.file_name().unwrap())),
            None,
        )
        .unwrap();

        assert_eq!(summary.total, 3);
        assert_eq!(summary.succeeded, 3);
        assert_eq!(summary.failed, 0);
        assert!(summary.is_ok());

        // Verify all outputs are encrypted and can be decrypted back.
        for (i, src) in sources.iter().enumerate() {
            let enc_path = out_dir.path().join(src.file_name().unwrap());
            let enc = fs::read(&enc_path).unwrap();
            assert_eq!(&enc[0..5], MAGIC);

            // Decrypt back and verify
            let dec_path = out_dir.path().join(format!("dec_{i}"));
            decrypt_file_to(&enc_path, &dec_path, master_key).unwrap();
            assert_eq!(
                fs::read(&dec_path).unwrap(),
                format!("source item {i}").as_bytes()
            );
        }
    }

    #[test]
    fn test_encrypt_files_to_with_compression() {
        let master_key = b"batch_compress_password";

        // Highly compressible data
        let temp_path = create_temp_file(&b"Z".repeat(30_000));
        let sources: Vec<PathBuf> = vec![temp_path.to_path_buf()];

        let out_dir = tempfile::TempDir::new().unwrap();
        let summary = encrypt_files_to(
            &sources,
            master_key,
            |src: &Path| Some(out_dir.path().join(src.file_name().unwrap())),
            Some(15),
        )
        .unwrap();

        assert_eq!(summary.succeeded, 1);

        // Compressed output should be much smaller.
        let enc_path = out_dir.path().join(sources[0].file_name().unwrap());
        assert!(fs::metadata(&enc_path).unwrap().len() < 5_000);
    }
}
