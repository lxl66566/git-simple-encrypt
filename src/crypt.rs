//! The core of this program. Encrypt/decrypt, compress/decompress files.
//!
//! GITSE Binary Header Layout (64 Bytes)
//!  00          04  05  06  07          17                 2F              3F
//!  +-----------+---+---+---+-----------+-------------------+---------------+
//!  |   MAGIC   | V | F | A |   SALT    |       NONCE       |   RESERVED    |
//!  |  "GITSE"  |   |   |   | (16 bytes)|    (24 bytes)     |  (16 bytes)   |
//!  +-----------+---+---+---+-----------+-------------------+---------------+
//!    5 bytes     1   1   1    16 bytes       24 bytes          16 bytes
//!                |   |   |
//!     Version ---+   |   +--- Encryption Algo (1 = XChaCha20-Poly1305 Stream)
//!                    |
//!      Flags --------+ (Bit 0: Compression)
//!
//! Streaming Format:
//! Files are processed in 64KB chunks to prevent OOM on large files.
//! Each chunk is individually encrypted using XChaCha20-Poly1305.
//! The nonce for chunk `i` is derived by `XORing` the last 8 bytes of the base
//! nonce with `i`.

use std::{
    fs,
    io::{Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
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
use rand::prelude::*;
use rayon::prelude::*;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use crate::{repo::Repo, salt_cache, utils::list_files};

// --- Constants & Header Layout ---

const MAGIC: &[u8; 5] = b"GITSE";
const VERSION: u8 = 2;
const FLAG_COMPRESSED: u8 = 1 << 0; // Bit 0
const ENC_ALGO: u8 = 1; // 1 = XChaCha20-Poly1305

// Sizes
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24; // XChaCha20 uses a 192-bit (24-byte) nonce
const HEADER_LEN: usize = 64;
const RESERVED_LEN: usize = HEADER_LEN - (MAGIC.len() + 1 + 1 + 1 + SALT_LEN + NONCE_LEN); // 16 bytes

// Streaming
const CHUNK_SIZE: usize = 65536; // 64 KB chunks

// --- Helper Structures ---

#[derive(Debug)]
pub struct FileHeader {
    version: u8,
    flags: u8,
    enc_algo: u8,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

impl FileHeader {
    #[must_use]
    pub fn new(compressed: bool, salt: [u8; SALT_LEN], nonce: Option<[u8; NONCE_LEN]>) -> Self {
        let nonce = nonce.unwrap_or_else(|| {
            let mut rng = rand::rng();
            let mut n = [0u8; NONCE_LEN];
            rng.fill_bytes(&mut n);
            n
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
            nonce,
        }
    }

    /// Write the header to the writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(MAGIC)?;
        writer.write_u8(self.version)?;
        writer.write_u8(self.flags)?;
        writer.write_u8(self.enc_algo)?;
        writer.write_all(&self.salt)?;
        writer.write_all(&self.nonce)?;
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
        if version != VERSION {
            return Err(anyhow!("Unsupported version: {version}"));
        }

        let flags = reader.read_u8()?;
        let enc_algo = reader.read_u8()?;
        if enc_algo != ENC_ALGO {
            return Err(anyhow!("Unsupported encryption algorithm: {enc_algo}"));
        }

        let mut salt = [0u8; SALT_LEN];
        reader.read_exact(&mut salt)?;
        let mut nonce = [0u8; NONCE_LEN];
        reader.read_exact(&mut nonce)?;
        let mut reserved = [0u8; RESERVED_LEN];
        reader.read_exact(&mut reserved)?;

        Ok(Self {
            version,
            flags,
            enc_algo,
            salt,
            nonce,
        })
    }

    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        (self.flags & FLAG_COMPRESSED) != 0
    }

    #[must_use]
    pub const fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    #[must_use]
    pub const fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }
}

// --- Core Logic ---

/// Derive a file-specific key using Argon2.
/// Input: User Master Key (bytes) + File Salt.
/// Output: 32 bytes (for XChaCha20-Poly1305).
fn derive_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(password, salt, &mut *key)
        .map_err(|e| anyhow!("Argon2 key derivation failed: {e}"))?;
    Ok(key)
}

/// Derive a unique nonce for each chunk.
/// Uses a 16-byte random prefix (from [`base_nonce`]) + 8-byte chunk counter.
fn derive_nonce(base_nonce: &[u8; NONCE_LEN], chunk_idx: u64) -> XNonce {
    let mut nonce_bytes = *base_nonce;
    nonce_bytes[16..24].copy_from_slice(&chunk_idx.to_le_bytes());
    XNonce::from(nonce_bytes)
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

// --- Public Operations ---

/// Encrypt a single file using streaming chunked encryption.
///
/// Returns `Some(header)` on success, or `None` if the file was already
/// encrypted and skipped.
pub fn encrypt_file(
    path: &Path,
    derived_key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    nonce: Option<[u8; NONCE_LEN]>,
    zstd: Option<u8>,
) -> Result<Option<FileHeader>> {
    let mut file = fs::File::open(path)?;

    // 1. Quick check if already encrypted (Redundant I/O fixed)
    let mut header_bytes = [0u8; HEADER_LEN];
    if file.read_exact(&mut header_bytes).is_ok()
        && &header_bytes[0..5] == MAGIC
        && header_bytes[5] == VERSION
    {
        warn!("File already encrypted, skipping: {}", path.display());
        return Ok(None);
    }
    file.seek(SeekFrom::Start(0))?; // Rewind to start

    debug!("Encrypting: {}", path.display());

    // 2. Prepare Header & Temp File
    let header = FileHeader::new(zstd.is_some(), *salt, nonce);
    let parent_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp_file = NamedTempFile::new_in(parent_dir)
        .with_context(|| "Failed to create temp file".to_string())?;

    header.write(&mut temp_file)?;

    // 3. Setup Streaming Pipeline
    let cipher = XChaCha20Poly1305::new(derived_key.into());

    // If compression is enabled, wrap the file reader in a Zstd Encoder
    let mut reader: Box<dyn Read> = if let Some(zstd_level) = zstd {
        Box::new(zstd::stream::read::Encoder::new(
            file,
            i32::from(zstd_level),
        )?)
    } else {
        Box::new(file)
    };

    // 4. Chunked Encryption Loop (OOM risk fixed, Zeroizing applied)
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
        let aad = if is_last_chunk { b"LAST" } else { b"MORE" };
        let nonce = derive_nonce(&header.nonce, chunk_idx);

        let payload = Payload {
            msg: &buffer[..bytes_read],
            aad,
        };

        let ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|e| anyhow!("Encryption failed: {e}"))?;

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
/// cache for derived keys and an optional salt cache for deterministic
/// re-encryption.
///
/// # Panics
///
/// Panics if the cache is poisoned.
#[allow(clippy::type_complexity)]
pub fn decrypt_file_with_cache<S: ::std::hash::BuildHasher + Clone>(
    path: &Path,
    key_cache: &DashMap<[u8; SALT_LEN], Zeroizing<[u8; 32]>, S>,
    salt_cache: Option<&salt_cache::SaltCache>,
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
    if &header_bytes[0..5] != MAGIC || header_bytes[5] != VERSION {
        debug!(
            "File not encrypted (no magic), skipping: {}",
            path.display()
        );
        return Ok(());
    }

    debug!("Decrypting: {}", path.display());
    let header = FileHeader::read(&mut Cursor::new(&header_bytes))
        .with_context(|| format!("Corrupt header in {}", path.display()))?;

    // Cache the salt+nonce BEFORE decryption so it is preserved even if
    // decryption fails halfway through.
    if let Some(sc) = salt_cache {
        sc.insert(
            path,
            salt_cache::CachedEntry {
                salt: header.salt,
                nonce: header.nonce,
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

    // 3. Setup Streaming Pipeline
    let cipher = XChaCha20Poly1305::new(derived_key.as_ref().into());
    let parent_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp_file = NamedTempFile::new_in(parent_dir)
        .with_context(|| "Failed to create temp file".to_string())?;

    // 4. Chunked Decryption Loop
    if header.is_compressed() {
        let mut decoder = zstd::stream::write::Decoder::new(&mut temp_file)?.auto_flush();
        decrypt_chunks(&mut file, &mut decoder, &cipher, &header.nonce)?;
        decoder.flush()?;
    } else {
        decrypt_chunks(&mut file, &mut temp_file, &cipher, &header.nonce)?;
    }
    drop(file);

    // 5. Atomic Write with Metadata Preservation
    atomic_write_with_metadata(path, temp_file)?;

    Ok(())
}

/// Helper function to read ciphertext chunks, decrypt them, and write to the
/// destination.
fn decrypt_chunks(
    file: &mut fs::File,
    writer: &mut dyn Write,
    cipher: &XChaCha20Poly1305,
    base_nonce: &[u8; NONCE_LEN],
) -> Result<()> {
    // Ciphertext chunk size = Plaintext chunk size + 16 bytes (Poly1305 MAC tag)
    let mut buffer = vec![0u8; CHUNK_SIZE + 16];
    let mut chunk_idx = 0u64;
    let mut last_chunk_was_final = false;

    loop {
        let mut bytes_read = 0;
        while bytes_read < buffer.len() {
            let n = file.read(&mut buffer[bytes_read..])?;
            if n == 0 {
                break;
            }
            bytes_read += n;
        }

        if bytes_read == 0 {
            break; // EOF
        }

        let is_last_chunk = bytes_read < buffer.len();
        let aad = if is_last_chunk { b"LAST" } else { b"MORE" };
        let nonce = derive_nonce(base_nonce, chunk_idx);

        let payload = chacha20poly1305::aead::Payload {
            msg: &buffer[..bytes_read],
            aad,
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
/// Loads the salt+nonce cache (populated by a previous decrypt) and reuses
/// cached values so that decrypt→encrypt on unchanged content produces
/// byte-identical ciphertext. Files not in the cache share a single new
/// batch salt to minimise Argon2 overhead.
///
/// # Panics
/// Panics if the master key is not set.
pub fn encrypt_repo(repo: &'static Repo, paths: Vec<PathBuf>) -> Result<()> {
    let key = repo.get_key();
    assert!(!key.is_empty(), "Key must not be empty");

    let target_files = if paths.is_empty() {
        list_files(repo.conf.crypt_list.iter(), repo.path())
    } else {
        list_files(paths, repo.path())
    };
    ensure!(!target_files.is_empty(), "No file to encrypt");

    let salt_cache = salt_cache::SaltCache::load(repo.path());
    let key_cache: DashMap<[u8; SALT_LEN], Zeroizing<[u8; 32]>> = DashMap::new();

    // Generate a single batch salt for files that have no cache entry.
    // This preserves the original performance characteristic of one Argon2
    // call for a full-batch encrypt.
    let mut batch_salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut batch_salt);

    let result = target_files.par_iter().try_for_each(|f| -> Result<()> {
        let (salt, cached_nonce) = salt_cache
            .get(f)
            .map_or((batch_salt, None), |entry| (entry.salt, Some(entry.nonce)));

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
            cached_nonce,
            repo.conf.use_zstd.then_some(repo.conf.zstd_level),
        )
        .with_context(|| format!("Failed to encrypt {}", f.display()))?;

        // Update cache with the salt+nonce used for this file.
        if let Some(h) = header {
            salt_cache.insert(
                f,
                salt_cache::CachedEntry {
                    salt: *h.salt(),
                    nonce: *h.nonce(),
                },
            );
        }

        Ok(())
    });

    // Always save the cache — even on partial failure the successfully
    // processed entries should be preserved for the next run.
    salt_cache.save();

    result?;
    Ok(())
}

/// Decrypt given files in the repo. If no paths are given, decrypt all files
/// in the repo's crypt list.
///
/// The salt+nonce of each successfully parsed encrypted file is captured into
/// the persistent salt cache so that a subsequent encrypt can reproduce
/// identical ciphertext.
///
/// # Panics
/// Panics if the master key is not set.
pub fn decrypt_repo(repo: &'static Repo, paths: Vec<PathBuf>) -> Result<()> {
    let key = repo.get_key();
    assert!(!key.is_empty(), "Master key must not be empty");

    let target_files = if paths.is_empty() {
        list_files(repo.conf.crypt_list.iter(), repo.path())
    } else {
        list_files(paths, repo.path())
    };
    ensure!(!target_files.is_empty(), "No file to decrypt");

    let key_cache: DashMap<[u8; SALT_LEN], Zeroizing<[u8; 32]>> = DashMap::new();
    let salt_cache = salt_cache::SaltCache::load(repo.path());

    let result = target_files
        .par_iter()
        .filter(|p| p.is_file())
        .try_for_each(|f| -> Result<()> {
            decrypt_file_with_cache(f, &key_cache, Some(&salt_cache), key.as_bytes())
                .with_context(|| format!("Failed to decrypt {}", f.display()))
        });

    // Always save the salt cache — even on partial failure the extracted
    // entries are valuable for the next encrypt run.
    salt_cache.save();

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
        assert_eq!(decoded.nonce, header.nonce);
        assert!(decoded.is_compressed());
    }

    #[test]
    fn test_nonce_derivation() {
        let base_nonce = [0u8; NONCE_LEN];

        // Chunk 0: Should be identical to base_nonce
        let nonce0 = derive_nonce(&base_nonce, 0);
        assert_eq!(nonce0.as_slice(), &[0u8; NONCE_LEN]);

        // Chunk 1: The 16th byte (index 16) should be XORed with 1
        let nonce1 = derive_nonce(&base_nonce, 1);
        let mut expected1 = [0u8; NONCE_LEN];
        expected1[16] = 1;
        assert_eq!(nonce1.as_slice(), &expected1);

        // Chunk 256: The 17th byte (index 17) should be XORed with 1 (256 is 0x0100 in
        // LE)
        let nonce256 = derive_nonce(&base_nonce, 256);
        let mut expected256 = [0u8; NONCE_LEN];
        expected256[17] = 1;
        assert_eq!(nonce256.as_slice(), &expected256);
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
    fn test_deterministic_encrypt_with_fixed_salt_nonce() {
        let plaintext = b"Deterministic encryption test data.";

        let password = b"test_password";
        let salt = [0x42; SALT_LEN];
        let nonce = [0x13; NONCE_LEN];
        let derived = derive_key(password, &salt).unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(&*derived);

        // Encrypt twice with the same salt+nonce → identical ciphertext
        let path1 = create_temp_file(plaintext);
        let path2 = create_temp_file(plaintext);

        encrypt_file(&path1, &key, &salt, Some(nonce), None).unwrap();
        encrypt_file(&path2, &key, &salt, Some(nonce), None).unwrap();

        let ct1 = fs::read(&path1).unwrap();
        let ct2 = fs::read(&path2).unwrap();
        assert_eq!(
            ct1, ct2,
            "Same plaintext + same salt+nonce must produce identical ciphertext"
        );

        // And both should decrypt correctly
        decrypt_file(&path1, password).unwrap();
        assert_eq!(fs::read(&path1).unwrap(), plaintext);
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
