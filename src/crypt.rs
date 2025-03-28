use std::{
    path::{Path, PathBuf},
    sync::LazyLock as Lazy,
};

use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes128GcmSiv, Nonce,
};
use anyhow::{anyhow, Context, Result};
use colored::Colorize;
use copy_metadata::copy_metadata;
use die_exit::{die, DieWith};
use glob::Pattern;
use log::{debug, info};
use sha3::{Digest, Sha3_224};
use tap::Tap;

extern crate test;

#[cfg(any(test, debug_assertions))]
use crate::utils::format_hex;
use crate::{
    repo::{GitCommand, Repo},
    utils::pathutils::{Git2Patch, PathAppendExt},
};

static NONCE: Lazy<&Nonce> = Lazy::new(|| Nonce::from_slice(b"samenonceplz"));
pub static ENCRYPTED_EXTENSION: &str = "enc";
pub static COMPRESSED_EXTENSION: &str = "zst";

pub fn calculate_key_sha(key: String) -> Vec<u8> {
    let mut hasher = Sha3_224::default();
    hasher.update(key);
    let hash_result = hasher.finalize();
    let hash_result_slice = hash_result.as_slice();
    let hash_result_slice_cut = &hash_result_slice[..16];
    hash_result_slice_cut.to_vec()
}

pub fn encrypt(key: &[u8], text: Box<[u8]>) -> std::result::Result<Vec<u8>, aes_gcm_siv::Error> {
    let cipher = Aes128GcmSiv::new_from_slice(key).expect("cipher key length error.");
    let encrypted = cipher.encrypt(*NONCE, text.as_ref())?;

    #[cfg(any(test, debug_assertions))]
    println!("Encrypted data: {}", format_hex(&encrypted).green());

    Ok(encrypted)
}

pub fn decrypt(key: &[u8], text: Box<[u8]>) -> std::result::Result<Vec<u8>, aes_gcm_siv::Error> {
    let cipher = Aes128GcmSiv::new_from_slice(key).expect("cipher key length error.");
    let plaintext = cipher.decrypt(*NONCE, text.as_ref())?;
    Ok(plaintext)
}

pub fn encrypt_change_path(
    key: &[u8],
    text: Box<[u8]>,
    path: PathBuf,
) -> Result<(Vec<u8>, PathBuf)> {
    Ok((
        encrypt(key, text).map_err(|e| anyhow!("`{:?}`: {e}", path))?,
        path.append_ext(ENCRYPTED_EXTENSION),
    ))
}

/// Try to decrypt bytes only if path ends with [`ENCRYPTED_EXTENSION`].
pub fn try_decrypt_change_path(
    key: &[u8],
    text: Box<[u8]>,
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
        Ok((text.into_vec(), path))
    }
}

/// Try to compress bytes, returns a [`PathBuf`] appended by
/// [`COMPRESSED_EXTENSION`]. If the compressed size is larger than origin, do
/// not change bytes and path.
fn try_compress(bytes: Box<[u8]>, path: PathBuf, level: u8) -> anyhow::Result<(Vec<u8>, PathBuf)> {
    let compressed =
        zstd::stream::encode_all(bytes.as_ref(), i32::from(level)).map_err(|e| anyhow!(e))?;

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
        Ok((bytes.into_vec(), path))
    }
}

/// Try to decompress bytes only if path ends with [`COMPRESSED_EXTENSION`].
fn try_decompress(bytes: Box<[u8]>, path: PathBuf) -> anyhow::Result<(Vec<u8>, PathBuf)> {
    if let Some(ext) = path.extension()
        && ext.to_str() == Some(COMPRESSED_EXTENSION)
    {
        let decompressed = zstd::stream::decode_all(bytes.as_ref()).map_err(|e| anyhow!(e))?;
        Ok((decompressed, path.with_extension("")))
    } else {
        debug!(
            "Extension of file `{:?}` does not match, do not decompress",
            path
        );
        Ok((bytes.into_vec(), path))
    }
}

/// encrypt file, and unlink it.
pub async fn encrypt_file(
    file: impl AsRef<Path> + Send + Sync,
    key: &'static [u8],
    zstd_level: u8,
) -> anyhow::Result<PathBuf> {
    let file = file.as_ref();
    debug!("encrypt_file accept: {:?}", file);
    debug_assert!(file.exists());
    debug_assert!(file.is_file());
    let new_file = file.to_owned();
    if file.extension() == Some(ENCRYPTED_EXTENSION.as_ref()) {
        info!(
            "{}",
            format!("Warning: file has been encrypted, do not encrypt: {file:?}").yellow()
        );
        return Ok(new_file);
    }
    println!("Encrypting file: {}", format!("{file:?}").green());
    let bytes = tokio::fs::read(file)
        .await
        .with_context(|| format!("{file:?}"))?;

    let (encrypted, new_file) = tokio::task::spawn_blocking(move || {
        let (compressed, new_file) = try_compress(bytes.into_boxed_slice(), new_file, zstd_level)?;
        encrypt_change_path(key, compressed.into_boxed_slice(), new_file)
    })
    .await??;

    tokio::fs::write(&new_file, encrypted).await?;
    copy_metadata(file, &new_file)?;
    tokio::fs::remove_file(file).await?;
    debug!("Encrypted filename: {:?}", new_file);
    Ok(new_file)
}

/// decrypt file, and unlink it.
pub async fn decrypt_file(
    file: impl AsRef<Path> + Send + Sync,
    key: &'static [u8],
) -> anyhow::Result<PathBuf> {
    println!(
        "Decrypting file: {}",
        format!("{}", file.as_ref().display()).green()
    );
    let new_file = file.as_ref().to_owned();
    let bytes = tokio::fs::read(&file)
        .await
        .with_context(|| format!("{}", file.as_ref().display()))?;

    let (decompressed, new_file) = tokio::task::spawn_blocking(move || {
        let (decrypted, new_file) =
            try_decrypt_change_path(key, bytes.into_boxed_slice(), new_file)?;
        try_decompress(decrypted.into_boxed_slice(), new_file)
    })
    .await??;

    tokio::fs::write(&new_file, decompressed).await?;
    copy_metadata(&file, &new_file)?;
    tokio::fs::remove_file(&file).await?;
    debug!("Decrypted filename: {:?}", new_file);
    Ok(new_file)
}

/// Encrypt all repo.
///
/// 1. add all (for the `ls-files` operation)
/// 2. `encrypt_file`
/// 3. add all
pub async fn encrypt_repo(repo: &'static Repo) -> anyhow::Result<()> {
    assert!(!repo.get_key().is_empty(), "Key must not be empty");
    let patterns = &repo.conf.crypt_list;
    if patterns.is_empty() {
        die!("No file to encrypt, please exec `git-se add <FILE>` first.");
    }
    repo.add_all()?;
    let encrypt_futures = repo
        .ls_files_absolute_with_given_patterns(
            &patterns.iter().map(|x| x as &str).collect::<Vec<&str>>(),
        )?
        .into_iter()
        .map(|f| encrypt_file(f, repo.get_key_sha(), repo.conf.zstd_level))
        .map(tokio::task::spawn)
        .collect::<Vec<_>>();
    for ret in encrypt_futures {
        if let Err(err) = ret.await? {
            eprintln!(
                "{}",
                format!("warning: failed to encrypt file: {err}").yellow()
            );
        }
    }
    repo.add_all()?;
    Ok(())
}

pub async fn decrypt_repo(repo: &'static Repo, path: Option<&String>) -> anyhow::Result<()> {
    assert!(!repo.get_key().is_empty(), "Key must not be empty");
    let dot_pattern = String::from("*.") + ENCRYPTED_EXTENSION;

    // partial decrypt filter
    let pattern: Option<Pattern> = path.as_ref().map(|x| {
        glob::Pattern::new(
            repo.path
                .join(Path::new(x.as_str()).patch())
                .to_string_lossy()
                .as_ref()
                .tap(|x| println!("Decrypting with pattern: {}", x.green())),
        )
        .die_with(|e| format!("Invalid pattern: {e}"))
    });
    let decrypt_path_filter: Box<dyn Fn(&PathBuf) -> bool> = if path.is_some() {
        Box::new(|path: &PathBuf| -> bool {
            pattern
                .as_ref()
                .expect("path must be Some in this case")
                .matches(path.to_string_lossy().as_ref())
        })
    } else {
        Box::new(|_: &PathBuf| -> bool { true })
    };

    let decrypt_futures = repo
        .ls_files_absolute_with_given_patterns(&[dot_pattern.as_str()])?
        .into_iter()
        .filter(|x| x.is_file())
        .filter(decrypt_path_filter)
        .map(|f| decrypt_file(f, repo.get_key_sha()))
        .map(tokio::task::spawn)
        .collect::<Vec<_>>();
    for ret in decrypt_futures {
        if let Err(err) = ret.await? {
            eprintln!(
                "{}",
                format!("warning: failed to decrypt file: {err}").yellow()
            );
        }
    }
    repo.add_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use rand::{Rng, SeedableRng};
    use test::Bencher;

    use super::*;
    use crate::config::Config;
    #[test]
    fn test_encrypt_decrypt() {
        let key = b"602bdc204140db0a";
        let content = b"456789";
        let encrypted_content = encrypt(key, Box::new(*content)).unwrap();
        assert_ne!(content.to_vec(), encrypted_content);
        let decrypted_content = decrypt(key, encrypted_content.into()).unwrap();
        assert_eq!(content.to_vec(), decrypted_content);
    }

    // region bench

    const FILE_SIZE: usize = 100;

    fn random_vec() -> Vec<u8> {
        let mut rng =
            rand::rngs::SmallRng::from_seed([0, 1].repeat(16).as_slice().try_into().unwrap());
        let mut v = Vec::with_capacity(FILE_SIZE);
        for _ in 0..FILE_SIZE {
            v.push(rng.random::<u8>());
        }
        v
    }

    #[bench]
    fn bench_encrypt(b: &mut Bencher) {
        let key = &calculate_key_sha("602bdc204140db0a".to_owned());
        let random_vec = random_vec();
        b.iter(move || {
            test::black_box(encrypt(key, random_vec.clone().into_boxed_slice()).unwrap());
        });
    }

    #[bench]
    fn bench_encrypt_file(b: &mut Bencher) -> Result<()> {
        let key = calculate_key_sha("602bdc204140db0a".to_owned());
        let key_static = Box::leak(Box::new(key)).as_slice();
        let random_vec = random_vec();
        let tempfile = tempfile::NamedTempFile::new().unwrap();
        let temp_path = tempfile.path();

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        b.iter(move || {
            std::fs::write(temp_path, random_vec.as_slice()).unwrap();
            test::black_box(rt.block_on(async move {
                encrypt_file(&temp_path, key_static, Config::default().zstd_level)
                    .await
                    .unwrap()
            }));
        });
        Ok(())
    }
}
