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
//! Each encrypted chunk layout: `[NONCE (24B)] [CIPHERTEXT] [TAG (16B)]`

use std::{
    fs,
    io::{Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

use anyhow::{Context, Result, anyhow, ensure};
use argon2::Argon2;
use byteorder::{ReadBytesExt, WriteBytesExt};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use dashmap::DashMap;
use log::{debug, warn};
use path_absolutize::Absolutize as _;
use pathdiff::diff_paths;
use rand::prelude::*;
use rayon::prelude::*;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use crate::{
    Repo,
    salt_cache::{self, CachedEntry, SaltCacheSender},
    utils::{
        create_progress_bar, is_file_encrypted, print_post_report, print_pre_report,
        resolve_target_files,
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

#[derive(Debug)]
pub struct FileHeader {
    version: u8,
    flags: u8,
    enc_algo: u8,
    salt: [u8; SALT_LEN],
    file_id: [u8; FILE_ID_LEN],
}

impl FileHeader {
    #[must_use]
    pub fn new(compressed: bool, salt: [u8; SALT_LEN], file_id: Option<[u8; FILE_ID_LEN]>) -> Self {
        let file_id = file_id.unwrap_or_else(|| {
            let mut rng = rand::rng();
            let mut id = [0u8; FILE_ID_LEN];
            rng.fill_bytes(&mut id);
            id
        });

        let mut flags = 0u8;
        if compressed {
            flags |= FLAG_COMPRESSED;
        }

        Self {
            version: VERSION,
            flags,
            enc_algo: ENC_ALGO,
            salt,
            file_id,
        }
    }

    /// Write the header to the writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(MAGIC)?;
        writer.write_u8(self.version)?;
        writer.write_u8(self.flags)?;
        writer.write_u8(self.enc_algo)?;
        writer.write_all(&self.salt)?;
        writer.write_all(&self.file_id)?;
        let reserved = [0u8; RESERVED_LEN];
        writer.write_all(&reserved)?;
        Ok(())
    }

    /// Read the header from the reader.
    pub fn read<R: Read>(reader: &mut R) -> Result<Self> {
        let mut magic_buf = [0u8; 5];
        reader
            .read_exact(&mut magic_buf)
            .context("Failed to read magic")?;
        if &magic_buf != MAGIC {
            return Err(anyhow!("Invalid magic bytes"));
        }

        let version = reader.read_u8()?;
        if !is_encrypted_version(version) {
            return Err(anyhow!("Unsupported version: {version}"));
        }

        let flags = reader.read_u8()?;
        let enc_algo = reader.read_u8()?;
        if enc_algo != ENC_ALGO {
            return Err(anyhow!("Unsupported encryption algorithm: {enc_algo}"));
        }

        let mut salt = [0u8; SALT_LEN];
        reader.read_exact(&mut salt)?;
        let mut file_id = [0u8; FILE_ID_LEN];
        reader.read_exact(&mut file_id)?;
        let mut reserved = [0u8; RESERVED_LEN];
        reader.read_exact(&mut reserved)?;

        Ok(Self {
            version,
            flags,
            enc_algo,
            salt,
            file_id,
        })
    }

    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        (self.flags & FLAG_COMPRESSED) != 0
    }
}

// --- Core Logic ---

/// Derive a file-specific key using Argon2.
/// Input: User Master Key (bytes) + File Salt.
/// Output: 32 bytes (master key, to be split into `Key_ENC` + `Key_MAC`).
fn derive_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(password, salt, &mut *key)
        .map_err(|e| anyhow!("Argon2 key derivation failed: {e}"))?;
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

/// Safely persist a temporary file while retaining the original file's metadata
/// (permissions, timestamps).
fn atomic_write_with_metadata(original_path: &Path, temp_file: NamedTempFile) -> Result<()> {
    // Attempt to copy metadata. If it fails, we log a warning but proceed to avoid
    // data loss.
    if let Err(e) = copy_metadata::copy_metadata(original_path, temp_file.path()) {
        warn!(
            "Could not copy metadata for {}: {}",
            original_path.display(),
            e
        );
    }
    temp_file.persist(original_path).with_context(|| {
        format!(
            "Failed to persist atomic write to {}",
            original_path.display()
        )
    })?;
    Ok(())
}

/// Compute a repo-relative cache key from a file path.
///
/// Uses `absolutize_from(repo_path)` to guarantee a correct absolute path
/// (even if `list_files` returns relative paths), then computes the relative
/// path via `diff_paths`. The result is raw OS-encoded bytes with `b'\\'`
/// replaced by `b'/'` for cross-platform consistency.
fn cache_key(file_path: &Path, repo_path: &Path) -> Vec<u8> {
    let abs_path = if file_path.is_absolute() {
        file_path.into()
    } else {
        file_path
            .absolutize_from(repo_path)
            .unwrap_or_else(|_| file_path.into())
    };
    let relative =
        diff_paths(abs_path.as_ref(), repo_path).unwrap_or_else(|| abs_path.to_path_buf());
    let mut bytes = relative.into_os_string().into_encoded_bytes();
    for b in &mut bytes {
        if *b == b'\\' {
            *b = b'/';
        }
    }
    bytes
}

// --- Public Operations ---

/// Encrypt a single file using streaming chunked encryption.
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
    let mut file = fs::File::open(path)?;

    // 1. Quick check if already encrypted
    let mut header_bytes = [0u8; HEADER_LEN];
    if file.read_exact(&mut header_bytes).is_ok()
        && &header_bytes[0..5] == MAGIC
        && is_encrypted_version(header_bytes[5])
    {
        warn!("File already encrypted, skipping: {}", path.display());
        return Ok(None);
    }
    file.seek(SeekFrom::Start(0))?; // Rewind to start

    debug!("Encrypting: {}", path.display());

    // 2. Generate File_ID (random if not cached) and prepare Header & Temp File
    let file_id = file_id.unwrap_or_else(|| {
        let mut rng = rand::rng();
        let mut id = [0u8; FILE_ID_LEN];
        rng.fill_bytes(&mut id);
        id
    });
    let header = FileHeader::new(zstd.is_some(), *salt, Some(file_id));
    let parent_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp_file = NamedTempFile::new_in(parent_dir)
        .with_context(|| "Failed to create temp file".to_string())?;

    header.write(&mut temp_file)?;

    // 3. Split master key into encryption key and MAC key, then setup cipher.
    let (key_enc, key_mac) = split_keys(derived_key);
    let cipher = XChaCha20Poly1305::new(key_enc.as_ref().into());

    // If compression is enabled, wrap the file reader in a Zstd Encoder
    let mut reader: Box<dyn Read> = if let Some(zstd_level) = zstd {
        Box::new(zstd::stream::read::Encoder::new(
            file,
            i32::from(zstd_level),
        )?)
    } else {
        Box::new(file)
    };

    // 4. Chunked Encryption Loop — content-based nonce derivation with File_ID
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
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
        let mut aad = [0u8; 9];
        aad[..8].copy_from_slice(&chunk_idx.to_le_bytes());
        aad[8] = u8::from(is_last_chunk);

        // Derive nonce from File_ID + current chunk's plaintext using keyed Blake3.
        let nonce_bytes = derive_nonce(&key_mac, &file_id, &buffer[..bytes_read], chunk_idx);
        let nonce = XNonce::from(nonce_bytes);

        let payload = Payload {
            msg: &buffer[..bytes_read],
            aad: &aad,
        };

        let ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|e| anyhow!("Encryption failed: {e}"))?;

        // Write: nonce (24B) + ciphertext (includes 16B Poly1305 tag).
        temp_file.write_all(&nonce_bytes)?;
        temp_file.write_all(&ciphertext)?;

        chunk_idx += 1;

        if is_last_chunk {
            break;
        }
    }

    // 5. Atomic Write with Metadata Preservation
    drop(reader);
    atomic_write_with_metadata(path, temp_file)?;

    Ok(Some(header))
}

/// Decrypt a single file using streaming chunked decryption.
pub fn decrypt_file(path: &Path, master_key: &[u8]) -> Result<()> {
    let key_cache = DashMap::new();
    decrypt_file_with_cache(path, &key_cache, None, master_key)
}

/// Decrypt a single file using streaming chunked decryption, with a thread-safe
/// cache for derived keys and an optional cache sender for deterministic
/// re-encryption.
///
/// The `cache` tuple contains `(sender, relative_key)` — the caller is
/// responsible for computing the repo-relative path key.
pub fn decrypt_file_with_cache(
    path: &Path,
    key_cache: &DashMap<[u8; SALT_LEN], Zeroizing<[u8; 32]>>,
    cache: Option<(&SaltCacheSender, &[u8])>,
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
    let header = FileHeader::read(&mut Cursor::new(&header_bytes))
        .with_context(|| format!("Corrupt header in {}", path.display()))?;

    // Cache the salt+file_id BEFORE decryption so it is preserved even if
    // decryption fails halfway through.
    if let Some((sender, key)) = cache {
        sender.insert(
            key,
            CachedEntry {
                salt: header.salt,
                file_id: header.file_id,
            },
        );
    }

    // 2. Retrieve or Derive Key (Argon2 Performance fixed)
    let derived_key = {
        if let Some(k) = key_cache.get(&header.salt) {
            k.clone()
        } else {
            let k = derive_key(master_key, &header.salt)?;
            key_cache.insert(header.salt, k.clone());
            k
        }
    };

    // 3. Split master key and setup cipher
    let (key_enc, _key_mac) = split_keys(&derived_key);
    let cipher = XChaCha20Poly1305::new(key_enc.as_ref().into());
    let parent_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp_file = NamedTempFile::new_in(parent_dir)
        .with_context(|| "Failed to create temp file".to_string())?;

    // 4. Chunked Decryption Loop
    if header.is_compressed() {
        let mut decoder = zstd::stream::write::Decoder::new(&mut temp_file)?.auto_flush();
        decrypt_chunks(&mut file, &mut decoder, &cipher)?;
        decoder.flush()?;
    } else {
        decrypt_chunks(&mut file, &mut temp_file, &cipher)?;
    }
    drop(file);

    // 5. Atomic Write with Metadata Preservation
    atomic_write_with_metadata(path, temp_file)?;

    Ok(())
}

/// Helper function to read ciphertext chunks, decrypt them, and write to the
/// destination.
///
/// Chunk layout: `[NONCE (24B)] [CIPHERTEXT] [TAG (16B)]`
fn decrypt_chunks(
    file: &mut fs::File,
    writer: &mut dyn Write,
    cipher: &XChaCha20Poly1305,
) -> Result<()> {
    let mut nonce_buf = [0u8; NONCE_LEN];
    let mut ct_buffer = vec![0u8; CHUNK_SIZE + 16]; // ciphertext + Poly1305 tag
    let mut last_chunk_was_final = false;
    let mut chunk_idx = 0u64;

    loop {
        // Read the 24-byte nonce from the chunk header.
        match file.read_exact(&mut nonce_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }

        // Read ciphertext + tag (up to CHUNK_SIZE + 16 bytes).
        let mut bytes_read = 0;
        while bytes_read < ct_buffer.len() {
            let n = file.read(&mut ct_buffer[bytes_read..])?;
            if n == 0 {
                break;
            }
            bytes_read += n;
        }

        if bytes_read == 0 {
            return Err(anyhow!(
                "Truncated chunk: nonce present but no ciphertext follows"
            ));
        }

        let is_last_chunk = bytes_read < ct_buffer.len();

        let mut aad = [0u8; 9];
        aad[..8].copy_from_slice(&chunk_idx.to_le_bytes());
        aad[8] = u8::from(is_last_chunk);

        let nonce = XNonce::from(nonce_buf);
        let payload = chacha20poly1305::aead::Payload {
            msg: &ct_buffer[..bytes_read],
            aad: &aad,
        };

        let plaintext = Zeroizing::new(cipher.decrypt(&nonce, payload).map_err(|e| {
            anyhow!("Decryption failed (wrong password, corrupt, or tampered data): {e}")
        })?);

        writer.write_all(&plaintext)?;

        chunk_idx += 1;

        if is_last_chunk {
            last_chunk_was_final = true;
            break;
        }
    }

    if !last_chunk_was_final {
        return Err(anyhow!(
            "File truncation detected! The ciphertext is incomplete."
        ));
    }

    Ok(())
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
pub fn encrypt_repo(repo: &'static Repo, paths: &[PathBuf]) -> Result<()> {
    let key = repo.get_key();
    ensure!(!key.is_empty(), "Key must not be empty");

    let target_files = resolve_target_files(paths, &repo.conf.crypt_list, repo.path());
    ensure!(!target_files.is_empty(), "No file to encrypt");

    // Pre-operation report
    print_pre_report("Encrypting", &target_files, repo.path());

    // Read-only cache: mmap + rkyv zero-copy. No write during encryption.
    let reader = salt_cache::SaltCacheReader::load(repo.path());

    let key_cache: DashMap<[u8; SALT_LEN], Zeroizing<[u8; 32]>> = DashMap::new();

    // Generate a single batch salt for files that have no cache entry.
    let mut batch_salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut batch_salt);

    let pb = create_progress_bar(target_files.len(), "Encrypt");
    let skipped = AtomicUsize::new(0);
    let failed = AtomicUsize::new(0);

    let result = target_files.par_iter().try_for_each(|f| -> Result<()> {
        let relative_key = cache_key(f, repo.path());
        let (salt, cached_file_id) = reader
            .get(&relative_key)
            .map_or((batch_salt, None), |entry| {
                (entry.salt, Some(entry.file_id))
            });

        // Derive key — cached across threads to avoid redundant Argon2 work.
        let derived_key = {
            if let Some(k) = key_cache.get(&salt) {
                k.clone()
            } else {
                let k = derive_key(key.as_bytes(), &salt)?;
                key_cache.insert(salt, k.clone());
                k
            }
        };

        let header = encrypt_file(
            f,
            &derived_key,
            &salt,
            cached_file_id,
            repo.conf.use_zstd.then_some(repo.conf.zstd_level),
        )
        .with_context(|| format!("Failed to encrypt {}", f.display()))?;

        if header.is_none() {
            skipped.fetch_add(1, Ordering::Relaxed);
        }

        pb.inc(1);
        Ok(())
    });

    pb.finish_and_clear();

    print_post_report(
        "Encrypt",
        target_files.len(),
        skipped.load(Ordering::Relaxed),
        failed.load(Ordering::Relaxed),
    );

    result?;

    Ok(())
}

/// Decrypt given files in the repo. If no paths are given, decrypt all files
/// in the repo's crypt list.
///
/// The `salt+file_id` of each successfully parsed encrypted file is captured
/// via an mpsc channel so that a subsequent encrypt can reproduce identical
/// ciphertext.
pub fn decrypt_repo(repo: &'static Repo, paths: &[PathBuf]) -> Result<()> {
    let key = repo.get_key();
    ensure!(!key.is_empty(), "Master key must not be empty");

    let target_files = resolve_target_files(paths, &repo.conf.crypt_list, repo.path());
    ensure!(!target_files.is_empty(), "No file to decrypt");

    // Pre-operation report
    print_pre_report("Decrypting", &target_files, repo.path());

    let key_cache: DashMap<[u8; SALT_LEN], Zeroizing<[u8; 32]>> = DashMap::new();

    // Write-only: mpsc channel collects salt/file_id from rayon threads.
    let (sender, saver) = salt_cache::create_writer(repo.path());

    let pb = create_progress_bar(target_files.len(), "Decrypt");
    let skipped = AtomicUsize::new(0);
    let failed = AtomicUsize::new(0);

    let result = target_files.par_iter().try_for_each(|f| -> Result<()> {
        if !is_file_encrypted(f)? {
            skipped.fetch_add(1, Ordering::Relaxed);
            pb.inc(1);
            return Ok(());
        }

        let relative_key = cache_key(f, repo.path());

        let decrypt_result = decrypt_file_with_cache(
            f,
            &key_cache,
            Some((&sender, &relative_key)),
            key.as_bytes(),
        )
        .with_context(|| format!("Failed to decrypt {}", f.display()));

        if decrypt_result.is_err() {
            failed.fetch_add(1, Ordering::Relaxed);
        }

        pb.inc(1);
        decrypt_result
    });

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

    result?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};

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
        let header = FileHeader::new(true, salt, None);

        let mut buf = Vec::new();
        header.write(&mut buf).unwrap();

        assert_eq!(buf.len(), HEADER_LEN);

        let mut cursor = Cursor::new(buf);
        let decoded = FileHeader::read(&mut cursor).unwrap();

        assert_eq!(decoded.version, VERSION);
        assert_eq!(decoded.flags, FLAG_COMPRESSED);
        assert_eq!(decoded.enc_algo, ENC_ALGO);
        assert_eq!(decoded.salt, salt);
        assert_eq!(decoded.file_id, header.file_id);
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
                .contains("Decryption failed")
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
        let key_cache = DashMap::new();
        decrypt_file_with_cache(path, &key_cache, None, master_key).unwrap();

        // Check permissions after decryption
        let decrypted_perms = fs::metadata(path).unwrap().permissions();
        assert_eq!(decrypted_perms.mode() & 0o777, 0o755);
    }
}
