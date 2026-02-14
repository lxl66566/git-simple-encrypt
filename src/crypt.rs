use std::{
    fs,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
};

use aes_gcm_siv::{
    Aes256GcmSiv, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Context, Result, anyhow};
use byteorder::{ReadBytesExt, WriteBytesExt};
use colored::Colorize;
use hkdf::Hkdf;
use log::{debug, info, warn};
use rand::RngCore;
use rayon::prelude::*;
use sha2::Sha256;

use crate::repo::{GitCommand, Repo};

// --- Constants & Header Layout ---

const MAGIC: &[u8; 5] = b"GITSE";
const VERSION: u8 = 2;

// Flag bit definitions
const FLAG_COMPRESSED: u8 = 1 << 0; // Bit 0

// Sizes
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12; // Standard 96-bit nonce
const HEADER_LEN: usize = MAGIC.len() + 1 + 1 + SALT_LEN + NONCE_LEN; // 5 + 1 + 1 + 16 + 12 = 35 bytes

// --- Helper Structures ---

#[derive(Debug)]
struct FileHeader {
    version: u8,
    flags: u8,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

impl FileHeader {
    fn new(compressed: bool) -> Self {
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
            salt,
            nonce,
        }
    }

    fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(MAGIC)?;
        writer.write_u8(self.version)?;
        writer.write_u8(self.flags)?;
        writer.write_all(&self.salt)?;
        writer.write_all(&self.nonce)?;
        Ok(())
    }

    fn read<R: Read>(reader: &mut R) -> Result<Self> {
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
        let mut salt = [0u8; SALT_LEN];
        reader.read_exact(&mut salt)?;
        let mut nonce = [0u8; NONCE_LEN];
        reader.read_exact(&mut nonce)?;

        Ok(Self {
            version,
            flags,
            salt,
            nonce,
        })
    }

    const fn is_compressed(&self) -> bool {
        (self.flags & FLAG_COMPRESSED) != 0
    }
}

// --- Core Logic ---

/// Check if a file is already encrypted by verifying the magic header.
pub fn is_encrypted(path: &Path) -> bool {
    if let Ok(mut file) = fs::File::open(path) {
        let mut buffer = [0u8; 5];
        if matches!(file.read_exact(&mut buffer), Ok(())) {
            return &buffer == MAGIC;
        }
    }
    false
}

/// Derive a file-specific key using HKDF-SHA256.
/// Input: User Master Key (bytes) + File Salt.
/// Output: 32 bytes (for AES-256).
fn derive_key(master_key: &[u8], salt: &[u8]) -> Vec<u8> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut okm = [0u8; 32]; // AES-256 key size
    hkdf.expand(b"GITSE_FILE_KEY", &mut okm)
        .expect("HKDF expand failed"); // Should strictly not happen for correct lengths
    okm.to_vec()
}

/// Try to compress data. Returns (data, `is_compressed`).
fn try_compress(data: &[u8], level: u8) -> Result<(Vec<u8>, bool)> {
    // If data is too small, compression might add overhead or valid frames are
    // larger.
    if data.len() < 50 {
        return Ok((data.to_vec(), false));
    }

    let compressed = zstd::stream::encode_all(data, i32::from(level))?;

    #[cfg(any(test, debug_assertions))]
    debug!("Compression: {} -> {}", data.len(), compressed.len());

    if compressed.len() < data.len() {
        Ok((compressed, true))
    } else {
        Ok((data.to_vec(), false))
    }
}

/// Decompress data if the flag is set.
fn try_decompress(data: &[u8], compressed: bool) -> Result<Vec<u8>> {
    if compressed {
        zstd::stream::decode_all(data).map_err(|e| anyhow!(e))
    } else {
        Ok(data.to_vec())
    }
}

// --- Public Operations ---

/// Encrypt file in-place (conceptually).
/// Actually writes to a temp buffer then overwrites content.
/// Filename is preserved.
pub fn encrypt_file(
    file: impl AsRef<Path> + Send + Sync,
    master_key: &[u8], // This is the raw user password/key
    zstd_level: u8,
) -> Result<PathBuf> {
    let path = file.as_ref();

    if is_encrypted(path) {
        info!("File already encrypted, skipping: {}", path.display());
        return Ok(path.to_path_buf());
    }

    info!("Encrypting: {}", path.display().to_string().green());

    let plain_bytes = fs::read(path).with_context(|| format!("Reading {path:?}"))?;

    // 1. Compression
    let (payload_bytes, is_compressed) = try_compress(&plain_bytes, zstd_level)?;

    // 2. Prepare Header (Generates random Salt & Nonce)
    let header = FileHeader::new(is_compressed);

    // 3. Derive Key
    let file_key = derive_key(master_key, &header.salt);

    // 4. Encrypt
    let cipher =
        Aes256GcmSiv::new_from_slice(&file_key).map_err(|e| anyhow!("Key creation failed: {e}"))?;
    let nonce = Nonce::from_slice(&header.nonce);

    let ciphertext = cipher
        .encrypt(nonce, payload_bytes.as_slice())
        .map_err(|e| anyhow!("Encryption failed: {e}"))?;

    // 5. Write Header + Ciphertext
    // We construct the full binary blob in memory to ensure atomic-like write
    // logic, or use a buffered writer. For git files (usually < 100MB), memory
    // is fine.
    let mut final_data = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    header.write(&mut final_data)?;
    final_data.extend_from_slice(&ciphertext);

    fs::write(path, final_data).with_context(|| format!("Writing {path:?}"))?;

    // We don't change the path anymore
    Ok(path.to_path_buf())
}

pub fn decrypt_file(
    file: impl AsRef<Path> + Send + Sync,
    master_key: &[u8],
) -> Result<Option<PathBuf>> {
    let path = file.as_ref();

    // Check magic quickly before loading whole file
    if !is_encrypted(path) {
        debug!(
            "File not encrypted (no magic), skipping: {}",
            path.display()
        );
        return Ok(None);
    }

    info!("Decrypting: {}", path.display());

    let content = fs::read(path).with_context(|| format!("Reading {path:?}"))?;
    let mut cursor = Cursor::new(&content);

    // 1. Parse Header
    let header =
        FileHeader::read(&mut cursor).with_context(|| format!("Corrupt header in {path:?}"))?;

    // 2. Derive Key
    let file_key = derive_key(master_key, &header.salt);

    // 3. Decrypt
    let cipher =
        Aes256GcmSiv::new_from_slice(&file_key).map_err(|e| anyhow!("Key creation failed: {e}"))?;
    let nonce = Nonce::from_slice(&header.nonce);

    // The cursor position is now at the start of ciphertext
    #[allow(clippy::cast_possible_truncation)]
    let ciphertext = &content[(cursor.position() as usize)..];

    let plaintext_raw = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("Decryption failed (wrong password?): {e}"))?;

    // 4. Decompress
    let final_bytes = try_decompress(&plaintext_raw, header.is_compressed())?;

    // 5. Write back
    fs::write(path, final_bytes)?;

    Ok(Some(path.to_path_buf()))
}

// --- Repo Integration ---

pub fn encrypt_repo(repo: &'static Repo) -> Result<()> {
    let key = repo.get_key();
    assert!(!key.is_empty(), "Key must not be empty");

    let patterns = &repo.conf.crypt_list;
    if patterns.is_empty() {
        return Err(anyhow!("No pattern to encrypt"));
    }

    // 1. Make sure everything tracked is clean or we are about to modify worktree
    // Logic: Git add -> ls-files -> encrypt -> Git add
    repo.add_all()?;

    let target_files = repo.ls_files_absolute_with_given_patterns(
        &patterns.iter().map(|x| x as &str).collect::<Vec<&str>>(),
    )?;

    target_files
        .par_iter()
        .map(|f| encrypt_file(f, key.as_bytes(), repo.conf.zstd_level))
        .collect::<Vec<_>>() // force evaluation
        .into_iter()
        .for_each(|res| {
            if let Err(e) = res {
                warn!("Encryption warning: {e}");
            }
        });

    repo.add_all()?;
    Ok(())
}

pub fn decrypt_repo(repo: &'static Repo, path: Vec<PathBuf>) -> Result<()> {
    let key = repo.get_key();
    assert!(!key.is_empty(), "Key must not be empty");

    // Strategy: If path provided, find files inside. If not, use crypt_list.
    // Since we don't change extensions anymore, we rely on the crypt_list to know
    // what *should* be encrypted, or scan files for Magic header.
    // Better practice: Use ls-files based on crypt_list to limit scanning scope.

    let files_to_decrypt =
        if path.is_empty() {
            // Decrypt everything in crypt_list
            let patterns = repo
                .conf
                .crypt_list
                .iter()
                .map(std::string::String::as_str)
                .collect::<Vec<_>>();
            repo.ls_files_absolute_with_given_patterns(&patterns)?
        } else {
            let mut res = vec![];
            for p in path {
                if p.is_file() {
                    res.push(p);
                } else {
                    res.extend_from_slice(&repo.ls_files_absolute_with_given_patterns(&[
                        &format!("{}/**/*", p.display()),
                    ])?);
                }
            }
            res
        };
    files_to_decrypt
        .par_iter()
        .filter(|p| p.is_file()) // double check
        .map(|f| decrypt_file(f, key.as_bytes()))
        .collect::<Vec<_>>()
        .into_iter()
        .for_each(|res| {
            if let Err(e) = res {
                warn!("Decryption warning: {e}");
            }
        });

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::NamedTempFile;

    use super::*;
    use crate::{config::Config, utils::format_hex};

    fn test_basic(content: &[u8]) {
        let mut temp_file = NamedTempFile::new().unwrap();
        let key = "602bdc204140db0a".to_owned();

        temp_file.write_all(content).unwrap();
        let encrypted_file = encrypt_file(
            temp_file.path(),
            key.as_bytes(),
            Config::default().zstd_level,
        )
        .unwrap();
        let encrypted_content = fs::read(&encrypted_file).unwrap();
        dbg!(format_hex(&encrypted_content));
        assert_ne!(encrypted_content, content);
        let decrypted_file = decrypt_file(encrypted_file, key.as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(
            temp_file.path().to_string_lossy().as_bytes(),
            decrypted_file.to_string_lossy().as_bytes()
        );
    }

    #[test]
    fn test_encrypt_decrypt() {
        test_basic(b"Hello, world!");
        test_basic(&b"6".repeat(100));
    }
}
