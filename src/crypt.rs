use std::{
    ops::Deref,
    path::{Path, PathBuf},
    sync::LazyLock as Lazy,
};

use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes128GcmSiv, Nonce,
};
use anyhow::{anyhow, Context, Result};
#[cfg(any(test, debug_assertions))]
use colored::Colorize;
use log::{debug, info};
use sha3::{Digest, Sha3_224};
use tap::Tap;

#[cfg(any(test, debug_assertions))]
use crate::utils::format_hex;
use crate::{git_command::CONFIG, utils::AppendExt};

static NONCE: Lazy<&Nonce> = Lazy::new(|| Nonce::from_slice(b"samenonceplz"));
pub static ENCRYPTED_EXTENSION: &str = "enc";
pub static COMPRESSED_EXTENSION: &str = "zst";

pub fn encrypt(key: &[u8], text: &[u8]) -> std::result::Result<Vec<u8>, aes_gcm_siv::Error> {
    #[cfg(any(test, debug_assertions))]
    println!("Key: {}", String::from_utf8_lossy(key).green());
    let mut hasher = Sha3_224::default();
    hasher.update(key);
    let hash_result = hasher.finalize();
    let hash_result_slice = hash_result.as_slice();
    #[cfg(any(test, debug_assertions))]
    {
        println!("Hash result: {}", format_hex(hash_result_slice).green());
        println!(
            "Hash Cut result: {}",
            format_hex(&hash_result_slice[..16]).green()
        );
    }
    let cipher =
        Aes128GcmSiv::new_from_slice(&hash_result_slice[..16]).expect("cipher key length error.");
    let encrypted = cipher.encrypt(NONCE.deref(), text)?;

    #[cfg(any(test, debug_assertions))]
    println!("Encrypted data: {}", format_hex(&encrypted).green());

    Ok(encrypted)
}

pub fn decrypt(key: &[u8], text: &[u8]) -> std::result::Result<Vec<u8>, aes_gcm_siv::Error> {
    let mut hasher = Sha3_224::default();
    hasher.update(key);
    let cipher = Aes128GcmSiv::new_from_slice(&hasher.finalize().as_slice()[..16])
        .expect("cipher key length error.");
    let plaintext = cipher.decrypt(NONCE.deref(), text)?;
    Ok(plaintext)
}

pub fn encrypt_change_path(key: &[u8], text: &[u8], path: PathBuf) -> Result<(Vec<u8>, PathBuf)> {
    Ok((
        encrypt(key, text).map_err(|e| anyhow!("`{:?}`: {e}", path))?,
        path.append_ext(ENCRYPTED_EXTENSION),
    ))
}

/// Try to decrypt bytes only if path ends with [`ENCRYPTED_EXTENSION`].
pub fn try_decrypt_change_path(
    key: &[u8],
    text: &[u8],
    path: PathBuf,
) -> Result<(Vec<u8>, PathBuf)> {
    if let Some(ext) = path.extension()
        && ext.to_str() == Some(ENCRYPTED_EXTENSION)
    {
        Ok((
            decrypt(key, text).map_err(|e| anyhow!("`{:?}`: {e}", path))?,
            path.with_extension(""),
        ))
    } else {
        debug!(
            "Extension of file `{:?}` does not match, do not decrypt",
            path
        );
        Ok((text.to_vec(), path))
    }
}

/// Try to compress bytes, returns a [`PathBuf`] appended by
/// [`COMPRESSED_EXTENSION`]. If the compressed size is larger than origin, do
/// not change bytes and path.
fn try_compress(bytes: &[u8], path: PathBuf) -> anyhow::Result<(Vec<u8>, PathBuf)> {
    let compressed = zstd::stream::encode_all(bytes, CONFIG.zstd_level).map_err(|e| anyhow!(e))?;

    #[cfg(any(test, debug_assertions))]
    println!("Compressed data: {}", format_hex(&compressed).green());

    if compressed.len() < bytes.len() {
        Ok((
            compressed,
            path.append_ext(COMPRESSED_EXTENSION)
                .tap(|p| debug!("Compressed to: {:?}", p)),
        ))
    } else {
        info!("Compressed data size is larger than origin, do not compress.");
        Ok((bytes.to_vec(), path))
    }
}

/// Try to decompress bytes only if path ends with [`COMPRESSED_EXTENSION`].
fn try_decompress(bytes: &[u8], path: PathBuf) -> anyhow::Result<(Vec<u8>, PathBuf)> {
    if let Some(ext) = path.extension()
        && ext.to_str() == Some(COMPRESSED_EXTENSION)
    {
        let decompressed = zstd::stream::decode_all(bytes).map_err(|e| anyhow!(e))?;
        Ok((decompressed, path.with_extension("")))
    } else {
        debug!(
            "Extension of file `{:?}` does not match, do not decompress",
            path
        );
        Ok((bytes.to_vec(), path))
    }
}

/// encrypt file, and unlink it.
pub async fn encrypt_file(file: impl AsRef<Path>) -> anyhow::Result<PathBuf> {
    info!("Encrypting file: {:?}", file.as_ref());
    let bytes = compio::fs::read(file.as_ref())
        .await
        .with_context(|| format!("{:?}", file.as_ref()))?;
    let new_file = file.as_ref().to_owned();
    let (compressed, new_file) = try_compress(&bytes, new_file)?;
    let (encrypted, new_file) = encrypt_change_path(CONFIG.key.as_bytes(), &compressed, new_file)?;
    compio::fs::write(&new_file, encrypted).await.0?;
    debug!("Encrypted filename: {:?}", new_file);
    compio::fs::remove_file(file.as_ref()).await?;
    Ok(new_file)
}

/// decrypt file, and unlink it.
pub async fn decrypt_file(file: impl AsRef<Path>) -> anyhow::Result<PathBuf> {
    info!("Decrypting file: {:?}", file.as_ref());
    let new_file = file.as_ref().to_owned();
    let bytes = compio::fs::read(&file)
        .await
        .with_context(|| format!("{:?}", file.as_ref()))?;
    let (decrypted, new_file) = try_decrypt_change_path(CONFIG.key.as_bytes(), &bytes, new_file)?;
    let (decompressed, new_file) = try_decompress(&decrypted, new_file)?;
    debug!("Decrypted filename: {:?}", new_file);
    compio::fs::write(&new_file, decompressed).await.0?;
    compio::fs::remove_file(&file).await?;
    Ok(new_file)
}

#[cfg(test)]
mod test {
    use anyhow::Ok;
    use same_file::is_same_file;
    use temp_testdir::TempDir;

    use super::*;

    #[compio::test]
    async fn test_encrypt_decrypt() -> anyhow::Result<()> {
        let temp_dir = TempDir::default();
        let file = temp_dir.join("test_file.txt");

        let content = b"123456";
        std::fs::write(&file, content)?;
        let new_file = encrypt_file(&file).await?;

        assert!(is_same_file(
            &new_file,
            file.clone().append_ext(ENCRYPTED_EXTENSION)
        )?);
        assert!(!file.exists());
        assert!(new_file.exists());
        assert_ne!(content.to_vec(), std::fs::read(&new_file)?);

        decrypt_file(&new_file).await?;
        assert!(!new_file.exists());
        assert_eq!(std::fs::read(&file)?, b"123456");
        Ok(())
    }

    #[compio::test]
    async fn test_encrypt_decrypt_with_compress() -> anyhow::Result<()> {
        let temp_dir = TempDir::default();
        let file = temp_dir.join("test_file.txt");

        let content = &b"6".repeat(60); // This content will be compressed
        std::fs::write(&file, content)?;
        let new_file = encrypt_file(&file).await?;

        assert!(is_same_file(
            &new_file,
            file.clone()
                .append_ext(COMPRESSED_EXTENSION)
                .append_ext(ENCRYPTED_EXTENSION)
        )?);
        assert!(!file.exists());
        assert!(new_file.exists());
        assert_ne!(content, &std::fs::read(&new_file)?);

        decrypt_file(&new_file).await?;
        assert!(!new_file.exists());
        assert_eq!(&std::fs::read(&file)?, content);
        Ok(())
    }
}
