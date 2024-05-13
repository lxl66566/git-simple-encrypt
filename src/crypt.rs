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
use colored::Colorize;
use futures_util::{stream::FuturesOrdered, StreamExt};
use log::{debug, info};
use sha3::{Digest, Sha3_224};
use tap::Tap;

#[cfg(any(test, debug_assertions))]
use crate::utils::format_hex;
use crate::{
    repo::{GitCommand, Repo},
    utils::pathutils::*,
};

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
fn try_compress(bytes: &[u8], path: PathBuf, level: u8) -> anyhow::Result<(Vec<u8>, PathBuf)> {
    let compressed = zstd::stream::encode_all(bytes, level as i32).map_err(|e| anyhow!(e))?;

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
pub async fn encrypt_file(file: impl AsRef<Path>, repo: &Repo) -> anyhow::Result<PathBuf> {
    let file = file.as_ref();
    debug!("encrypt_file accept: {:?}", file);
    debug_assert!(file.exists());
    debug_assert!(file.is_file());
    let new_file = file.to_owned();
    if file.extension() == Some(ENCRYPTED_EXTENSION.as_ref()) {
        info!(
            "{}",
            format!(
                "Warning: file has been encrypted, do not encrypt: {:?}",
                file
            )
            .yellow()
        );
        return Ok(new_file);
    }
    println!("Encrypting file: {}", format!("{:?}", file).green());
    let bytes = compio::fs::read(file)
        .await
        .with_context(|| format!("{:?}", file))?;
    let (compressed, new_file) = try_compress(&bytes, new_file, repo.conf.zstd_level)?;
    let (encrypted, new_file) =
        encrypt_change_path(repo.get_key()?.as_bytes(), &compressed, new_file)?;
    compio::fs::write(&new_file, encrypted).await.0?;
    compio::fs::remove_file(file).await?;
    debug!("Encrypted filename: {:?}", new_file);
    Ok(new_file)
}

/// decrypt file, and unlink it.
pub async fn decrypt_file(file: impl AsRef<Path>, repo: &Repo) -> anyhow::Result<PathBuf> {
    println!(
        "Decrypting file: {}",
        format!("{:?}", file.as_ref()).green()
    );
    let new_file = file.as_ref().to_owned();
    let bytes = compio::fs::read(&file)
        .await
        .with_context(|| format!("{:?}", file.as_ref()))?;
    let (decrypted, new_file) =
        try_decrypt_change_path(repo.get_key()?.as_bytes(), &bytes, new_file)?;
    let (decompressed, new_file) = try_decompress(&decrypted, new_file)?;
    compio::fs::write(&new_file, decompressed).await.0?;
    compio::fs::remove_file(&file).await?;
    debug!("Decrypted filename: {:?}", new_file);
    Ok(new_file)
}

pub async fn encrypt_repo(repo: &Repo) -> anyhow::Result<()> {
    let patterns = &repo.conf.crypt_list;
    repo.add_all()?;
    let mut encrypt_futures = repo
        .ls_files_absolute_with_given_patterns(
            &patterns.iter().map(|x| x as &str).collect::<Vec<&str>>(),
        )?
        .into_iter()
        .map(|f| encrypt_file(f, repo))
        .collect::<FuturesOrdered<_>>();
    while let Some(ret) = encrypt_futures.next().await {
        if let Err(err) = ret {
            eprintln!(
                "{}",
                format!("warning: failed to encrypt file: {}", err).yellow()
            )
        }
    }
    repo.add_all()?;
    Ok(())
}

pub async fn decrypt_repo(repo: &Repo) -> anyhow::Result<()> {
    let dot_pattern = String::from("*.") + ENCRYPTED_EXTENSION;
    let mut decrypt_futures = repo
        .ls_files_absolute_with_given_patterns(&[dot_pattern.as_str()])?
        .into_iter()
        .filter(|x| x.is_file())
        .map(|f| decrypt_file(f, repo))
        .collect::<FuturesOrdered<_>>();
    while let Some(ret) = decrypt_futures.next().await {
        if let Err(err) = ret {
            eprintln!(
                "{}",
                format!("warning: failed to decrypt file: {}", err).yellow()
            )
        }
    }
    repo.add_all()?;
    Ok(())
}

#[cfg(test)]
mod test {
    use anyhow::Result;

    use super::*;

    #[test]
    fn test_encrypt_decrypt() -> Result<()> {
        let key = b"123456";
        let content = b"456789";
        let encrypted_content = encrypt(key, content).unwrap();
        assert_ne!(content.to_vec(), encrypted_content);
        let decrypted_content = decrypt(key, &encrypted_content).unwrap();
        assert_eq!(content.to_vec(), decrypted_content);
        Ok(())
    }
}
