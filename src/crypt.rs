#![allow(clippy::too_long_first_doc_paragraph)]

//! The core of this program. Encrypt/decrypt, compress/decompress files.
//! GITSE Binary Header Layout (64 Bytes)
//!  00          04  05  06  07          17                 23              3F
//!  +-----------+---+---+---+-----------+-------------------+---------------+
//!  |   MAGIC   | V | F | A |   SALT    |       NONCE       |   RESERVED    |
//!  |  "GITSE"  |   |   |   | (16 bytes)|    (12 bytes)     |  (28 bytes)   |
//!  +-----------+---+---+---+-----------+-------------------+---------------+
//!    5 bytes     1   1   1    16 bytes       12 bytes          28 bytes
//!                |   |   |
//!     Version ---+   |   +--- Encryption Algo (0 = AES-256-GCM)
//!                    |
//!      Flags --------+ (Bit 0: Compression)

use std::{
    borrow::Cow,
    fs,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
};

use aes_gcm_siv::{
    Aes256GcmSiv, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::{Context, Result, anyhow, ensure};
use argon2::Argon2;
use byteorder::{ReadBytesExt, WriteBytesExt};
use log::{debug, warn};
use rand::prelude::*;
use rayon::prelude::*;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use crate::{repo::Repo, utils::list_files};

// --- Constants & Header Layout ---

const MAGIC: &[u8; 5] = b"GITSE";
const VERSION: u8 = 2;
const FLAG_COMPRESSED: u8 = 1 << 0; // Bit 0
const ENC_ALGO: u8 = 0; // 0 = AES-256-GCM

// Sizes
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12; // Standard 96-bit nonce
const HEADER_LEN: usize = 64;
const RESERVED_LEN: usize = HEADER_LEN - (MAGIC.len() + 1 + 1 + 1 + SALT_LEN + NONCE_LEN); //  (64 - 5 - 1 - 1 - 1 - 16 - 12 = 28 bytes)

const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024; // 1 GB, warning for files > MAX_FILE_SIZE

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
    pub fn new(compressed: bool) -> Self {
        let mut rng = rand::rng();
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce);

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
}

impl TryFrom<&[u8]> for FileHeader {
    type Error = anyhow::Error;
    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        Self::read(&mut Cursor::new(&value))
    }
}

// --- Core Logic ---

pub fn is_encrypted(file: &mut fs::File, metadata: &fs::Metadata) -> Result<bool> {
    if metadata.len() < HEADER_LEN as u64 {
        return Ok(false);
    }

    // 2. MAGIC (5 bytes) + VERSION (1 byte)
    let mut buf = [0u8; 6];
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_exact_at(&mut buf, 0)?;
    }
    #[cfg(not(unix))]
    {
        use std::io::Seek;

        file.read_exact(&mut buf)?;
        file.rewind()?;
    }
    Ok(&buf[0..5] == MAGIC && buf[5] == VERSION)
}

/// Derive a file-specific key using Argon2.
/// Input: User Master Key (bytes) + File Salt.
/// Output: 32 bytes (for AES-256).
fn derive_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(password, salt, &mut *key)
        .map_err(|e| anyhow!("Argon2 key derivation failed: {e}"))?;
    Ok(key)
}

/// Try to compress data. Returns (data, `is_compressed`).
fn try_compress(data: &[u8], level: u8) -> Result<(Cow<'_, [u8]>, bool)> {
    // If data is too small, compression might add overhead or valid frames are
    // larger.
    if data.len() < 50 {
        return Ok((Cow::Borrowed(data), false));
    }
    let compressed = zstd::stream::encode_all(data, i32::from(level))?;

    #[cfg(any(test, debug_assertions))]
    debug!("Compression: {} -> {}", data.len(), compressed.len());

    if compressed.len() < data.len() {
        Ok((Cow::Owned(compressed), true))
    } else {
        Ok((Cow::Borrowed(data), false))
    }
}

/// Decompress data if the flag is set.
fn try_decompress(data: &[u8], compressed: bool) -> Result<Cow<'_, [u8]>> {
    if compressed {
        zstd::stream::decode_all(data)
            .map(Cow::Owned)
            .map_err(|e| anyhow!(e))
    } else {
        Ok(Cow::Borrowed(data))
    }
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp_file = NamedTempFile::new_in(parent_dir)
        .with_context(|| "Failed to create temp file".to_string())?;

    temp_file.write_all(data).with_context(|| {
        format!(
            "Failed to write data to temp file {}",
            temp_file.path().display()
        )
    })?;
    temp_file
        .persist(path)
        .with_context(|| format!("Failed to persist atomic write to {}", path.display()))?;
    Ok(())
}

// --- Public Operations ---

/// Encrypt file.
/// Actually writes to a temp buffer then overwrites content.
/// Filename is preserved.
pub fn encrypt_file(
    file: impl AsRef<Path> + Send + Sync,
    master_key: &[u8], // This is the raw user password/key
    zstd_level: u8,
) -> Result<()> {
    let path = file.as_ref();
    let mut file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    if is_encrypted(&mut file, &metadata)? {
        warn!("File already encrypted, skipping: {}", path.display());
        return Ok(());
    }
    if metadata.len() > MAX_FILE_SIZE {
        warn!(
            "File size too large ({} MB), please pay attention to memory usage: {}",
            metadata.len() / 1024 / 1024,
            path.display()
        );
    }

    debug!("Encrypting: {}", path.display());

    #[allow(clippy::cast_possible_truncation)]
    let mut plain_bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut plain_bytes)
        .with_context(|| format!("Reading {}", path.display()))?;
    drop(file);

    // 1. Compression
    let (payload_bytes, is_compressed) = try_compress(&plain_bytes, zstd_level)?;

    // 2. Prepare Header (Generates random Salt & Nonce)
    let header = FileHeader::new(is_compressed);

    // 3. Derive Key
    let file_key = derive_key(master_key, &header.salt)?;

    // 4. Encrypt
    let cipher = Aes256GcmSiv::new_from_slice(&*file_key)
        .map_err(|e| anyhow!("Key creation failed: {e}"))?;
    let nonce = Nonce::from_slice(&header.nonce);
    let mut header_bytes = Vec::with_capacity(HEADER_LEN);
    header.write(&mut header_bytes)?;
    let payload = Payload {
        msg: &payload_bytes,
        aad: &header_bytes,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| anyhow!("Encryption failed: {e}"))?;

    // 5. Write Header + Ciphertext
    // We construct the full binary blob in memory to ensure atomic-like write
    // logic, or use a buffered writer. For git files (usually < 100MB), memory
    // is fine.
    let mut final_data = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    header.write(&mut final_data)?;
    final_data.extend_from_slice(&ciphertext);

    atomic_write(path, &final_data)?;

    Ok(())
}

pub fn decrypt_file(file: impl AsRef<Path> + Send + Sync, master_key: &[u8]) -> Result<()> {
    let path = file.as_ref();
    let mut file = fs::File::open(path)?;
    let metadata = file.metadata()?;

    // Check magic quickly before loading whole file
    if !is_encrypted(&mut file, &metadata)? {
        debug!(
            "File not encrypted (no magic), skipping: {}",
            path.display()
        );
        return Ok(());
    }
    debug!("Decrypting: {}", path.display());

    #[allow(clippy::cast_possible_truncation)] // truncation is fine
    let mut content = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut content)
        .with_context(|| format!("Reading {}", path.display()))?;
    drop(file);

    let header_bytes = &content[0..HEADER_LEN];
    let header = FileHeader::try_from(header_bytes)
        .with_context(|| format!("Corrupt header in {}", path.display()))?;

    // 2. Derive Key
    let file_key = derive_key(master_key, &header.salt)?;

    // 3. Decrypt
    let cipher = Aes256GcmSiv::new_from_slice(&*file_key)
        .map_err(|e| anyhow!("Key creation failed: {e}"))?;
    let nonce = Nonce::from_slice(&header.nonce);
    let payload = Payload {
        msg: &content[HEADER_LEN..],
        aad: header_bytes,
    };
    let plaintext_raw = cipher
        .decrypt(nonce, payload)
        .map_err(|e| anyhow!("Decryption failed (wrong password or corrupt header): {e}"))?;

    // 4. Decompress
    let final_bytes = try_decompress(&plaintext_raw, header.is_compressed())?;

    // 5. Write back
    atomic_write(path, &final_bytes)?;

    Ok(())
}

// --- Repo Integration ---

/// Encrypt given files in the repo. If no paths are given, encrypt all files
/// in the repo's crypt list.
///
/// # Panics
///
/// Panics if the master key is not set.
pub fn encrypt_repo(repo: &'static Repo, paths: Vec<PathBuf>) -> Result<()> {
    let key = repo.get_key();
    assert!(!key.is_empty(), "Key must not be empty");

    let target_files = if paths.is_empty() {
        list_files(repo.conf.crypt_list.iter())
    } else {
        list_files(paths)
    };
    ensure!(!target_files.is_empty(), "No file to encrypt");
    target_files.par_iter().for_each(|f| {
        if let Err(e) = encrypt_file(f, key.as_bytes(), repo.conf.zstd_level) {
            warn!("Encryption warning for {}: {}", f.display(), e);
        }
    });
    Ok(())
}

/// Decrypt given files in the repo. If no paths are given, decrypt all files
/// in the repo's crypt list.
///
/// # Panics
///
/// Panics if the master key is not set.
pub fn decrypt_repo(repo: &'static Repo, paths: Vec<PathBuf>) -> Result<()> {
    let key = repo.get_key();
    assert!(!key.is_empty(), "Master key must not be empty");
    let target_files = if paths.is_empty() {
        list_files(repo.conf.crypt_list.iter())
    } else {
        list_files(paths)
    };
    ensure!(!target_files.is_empty(), "No file to decrypt");
    target_files
        .par_iter()
        .filter(|p| p.is_file()) // double check
        .for_each(|f| {
            if let Err(e) = decrypt_file(f, key.as_bytes()) {
                warn!("Decryption warning: {e}");
            }
        });

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use log::LevelFilter;
    use tempfile::NamedTempFile;

    use super::*;
    use crate::{config::Config, utils::format_hex};

    #[test]
    fn test_atomic_write() {
        let temp_file = NamedTempFile::new().unwrap();
        let temp_path = temp_file.into_temp_path();
        atomic_write(&temp_path, b"Hello, world!").unwrap();
        assert_eq!(fs::read(&temp_path).unwrap(), b"Hello, world!");
    }

    fn test_basic(content: &[u8]) {
        let mut temp_file = NamedTempFile::new().unwrap();
        println!("temp_file path: {:?}", temp_file.path());
        let key = "602bdc204140db0a".to_owned();

        temp_file.write_all(content).unwrap();
        let temp_path = temp_file.into_temp_path();

        encrypt_file(&temp_path, key.as_bytes(), Config::default().zstd_level).unwrap();
        let encrypted_content = fs::read(&temp_path).unwrap();
        dbg!(format_hex(&encrypted_content));
        assert_ne!(encrypted_content, content);
        decrypt_file(&temp_path, key.as_bytes()).unwrap();
        assert_eq!(fs::read(temp_path).unwrap(), content);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let _ = pretty_env_logger::formatted_builder()
            .filter_level(LevelFilter::Debug)
            .format_timestamp_millis()
            .parse_default_env()
            .try_init();
        test_basic(b"Hello, world!");
        test_basic(&b"6".repeat(100));
    }

    #[test]
    fn test_modified_header() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let key = "602bdc204140db0a".to_owned();

        temp_file.write_all(b"Hello, world!").unwrap();
        let temp_path = temp_file.into_temp_path();

        encrypt_file(&temp_path, key.as_bytes(), Config::default().zstd_level).unwrap();
        let mut encrypted_content = fs::read(&temp_path).unwrap();
        dbg!(format_hex(&encrypted_content));
        assert_ne!(encrypted_content, b"Hello, world!");
        encrypted_content[HEADER_LEN - 5] = 0x0F; // modify header byte
        fs::write(&temp_path, &encrypted_content).unwrap();
        let err = decrypt_file(&temp_path, key.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("aead::Error"));
    }
}
