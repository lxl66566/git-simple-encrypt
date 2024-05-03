use crate::git_command::CONFIG;
use crate::utils::AppendExt;
use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes128GcmSiv, Nonce,
};
use anyhow::{anyhow, Context};
use log::{debug, info};
use sha3::{Digest, Sha3_224};
use std::{ops::Deref, path::Path, sync::LazyLock as Lazy};

#[cfg(any(test, debug_assertions))]
use crate::utils::format_hex;
#[cfg(any(test, debug_assertions))]
use colored::Colorize;

type Result<T> = std::result::Result<T, aes_gcm_siv::Error>;

static NONCE: Lazy<&Nonce> = Lazy::new(|| Nonce::from_slice(b"samenonceplz"));
pub static ENCRYPTED_EXTENSION: &str = "zstenc";

pub fn encrypt(key: &[u8], text: &[u8]) -> Result<Vec<u8>> {
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
    let ciphertext = cipher.encrypt(NONCE.deref(), text)?;
    Ok(ciphertext)
}

pub fn decrypt(key: &[u8], text: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = Sha3_224::default();
    hasher.update(key);
    let cipher = Aes128GcmSiv::new_from_slice(&hasher.finalize().as_slice()[..16])
        .expect("cipher key length error.");
    let plaintext = cipher.decrypt(NONCE.deref(), text)?;
    Ok(plaintext)
}

fn compress(text: &[u8]) -> anyhow::Result<Vec<u8>> {
    zstd::stream::encode_all(text, CONFIG.zstd_level).map_err(|e| anyhow!(e))
}

fn decompress(text: &[u8]) -> anyhow::Result<Vec<u8>> {
    zstd::stream::decode_all(text).map_err(|e| anyhow!(e))
}

/// encrypt file, and unlink it.
pub async fn encrypt_file(file: impl AsRef<Path>) -> anyhow::Result<()> {
    info!("Encrypting file: {:?}", file.as_ref());
    let bytes = compio::fs::read(file.as_ref())
        .await
        .with_context(|| format!("{:?}", file.as_ref()))?;
    let new_file = file.as_ref().to_owned().append_ext();
    debug!("Encrypted filename: {:?}", new_file);
    let compressed = compress(&bytes).map_err(|e| anyhow!("`{:?}`: {e}", new_file))?;

    #[cfg(any(test, debug_assertions))]
    println!("Compressed data: {}", format_hex(&compressed).green());

    let encrypted = encrypt(CONFIG.key.as_bytes(), &compressed)
        .map_err(|e| anyhow!("`{:?}`: {e}", new_file))?;

    #[cfg(any(test, debug_assertions))]
    println!("Encrypted data: {}", format_hex(&encrypted).green());

    compio::fs::write(&new_file, encrypted).await.0?;
    compio::fs::remove_file(file.as_ref()).await?;
    Ok(())
}

/// decrypt file, and unlink it.
pub async fn decrypt_file(file: impl AsRef<Path>) -> anyhow::Result<()> {
    debug_assert!(file.as_ref().extension().unwrap() == ENCRYPTED_EXTENSION);
    info!("Decrypting file: {:?}", file.as_ref());
    let bytes = compio::fs::read(&file)
        .await
        .with_context(|| format!("{:?}", file.as_ref()))?;
    let mut new_file = file.as_ref().to_owned();
    new_file.set_extension("");
    debug!("Decrypted filename: {:?}", new_file);
    let decrypted =
        decrypt(CONFIG.key.as_bytes(), &bytes).map_err(|e| anyhow!("`{:?}`: {e}", new_file))?;
    let decompressed = decompress(&decrypted).map_err(|e| anyhow!("`{:?}`: {e}", new_file))?;
    compio::fs::write(&new_file, decompressed).await.0?;
    compio::fs::remove_file(&file).await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Ok;
    use temp_testdir::TempDir;

    #[compio::test]
    async fn test_encrypt_decrypt() -> anyhow::Result<()> {
        let temp_dir = TempDir::default();
        let file = temp_dir.join("test_file.txt");

        let content = b"123456";
        std::fs::write(&file, content)?;
        encrypt_file(&file).await?;
        let encrypted_file = file.parent().unwrap().join("test_file.txt").append_ext();

        assert!(!file.exists());
        assert!(encrypted_file.exists());
        assert_ne!(content.to_vec(), std::fs::read(&encrypted_file)?);

        decrypt_file(&encrypted_file).await?;
        assert_eq!(std::fs::read(&file)?, b"123456");
        Ok(())
    }
}
