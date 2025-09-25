use std::{
    fs,
    path::{Path, PathBuf},
    sync::LazyLock as Lazy,
};

use aes_gcm_siv::{
    Aes128GcmSiv, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Context, Result, anyhow};
use colored::Colorize;
use copy_metadata::copy_metadata;
use log::{debug, info, warn};
use rayon::{iter::IntoParallelRefIterator, prelude::*};
use sha3::{Digest, Sha3_224};
use tap::Tap;

extern crate test;

#[cfg(any(test, debug_assertions))]
use crate::utils::format_hex;
use crate::{
    repo::{GitCommand, Repo},
    utils::pathutils::PathAppendExt,
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
    decompress_if_needed: bool,
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
            "Extension of file `{}` does not match, do not decrypt",
            path.display()
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
                .tap(|p| debug!("Compressed to: `{}`", p.display())),
        ))
    } else {
        info!(
            "Compressed data size is larger than origin, do not compress `{}`.",
            path.display()
        );
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
            "Extension of file `{}` does not match, do not decompress",
            path.display()
        );
        Ok((bytes.into_vec(), path))
    }
}

/// encrypt file, and unlink it.
pub fn encrypt_file(
    file: impl AsRef<Path> + Send + Sync,
    key: &'static [u8],
    zstd_level: u8,
) -> anyhow::Result<PathBuf> {
    let file = file.as_ref();
    debug!("encrypt_file accept: {}", file.display());
    debug_assert!(file.exists());
    debug_assert!(file.is_file());
    let new_file = file.to_owned();
    if file.extension() == Some(ENCRYPTED_EXTENSION.as_ref()) {
        info!(
            "{}",
            format!(
                "Warning: file has been encrypted, do not encrypt: {}",
                file.display()
            )
            .yellow()
        );
        return Ok(new_file);
    }
    info!(
        "Encrypting file: `{}`",
        format!("{}", file.display()).green()
    );
    let bytes = fs::read(file).with_context(|| format!("{}", file.display()))?;

    let (encrypted, new_file) = {
        let (compressed, new_file) = try_compress(bytes.into_boxed_slice(), new_file, zstd_level)?;
        encrypt_change_path(key, compressed.into_boxed_slice(), new_file)
    }?;

    fs::write(&new_file, encrypted)?;
    copy_metadata(file, &new_file)?;
    fs::remove_file(file)?;
    debug!("Encrypted filename: {}", new_file.display());
    Ok(new_file)
}

/// decrypt file, and unlink it.
pub fn decrypt_file(
    file: impl AsRef<Path> + Send + Sync,
    key: &'static [u8],
) -> anyhow::Result<PathBuf> {
    info!("Decrypting file: {}", file.as_ref().display());
    let new_file = file.as_ref().to_owned();
    let bytes = fs::read(&file).with_context(|| format!("{}", file.as_ref().display()))?;

    let (decompressed, new_file) = {
        let (decrypted, new_file) =
            try_decrypt_change_path(key, bytes.into_boxed_slice(), new_file)?;
        try_decompress(decrypted.into_boxed_slice(), new_file)
    }?;

    fs::write(&new_file, decompressed)?;
    copy_metadata(&file, &new_file)?;
    fs::remove_file(&file)?;
    debug!("Decrypted filename: {}", new_file.display());
    Ok(new_file)
}

/// Encrypt all repo.
///
/// 1. add all (for the `ls-files` operation)
/// 2. `encrypt_file`
/// 3. add all
pub fn encrypt_repo(repo: &'static Repo) -> anyhow::Result<()> {
    assert!(!repo.get_key().is_empty(), "Key must not be empty");
    let patterns = &repo.conf.crypt_list;
    assert!(
        !patterns.is_empty(),
        "No file to encrypt, please exec `git-se add <FILE>` first."
    );
    repo.add_all()?;
    let encrypt_result = repo
        .ls_files_absolute_with_given_patterns(
            &patterns.iter().map(|x| x as &str).collect::<Vec<&str>>(),
        )?
        .par_iter()
        .map(|f| encrypt_file(f, repo.get_key_sha(), repo.conf.zstd_level))
        .collect::<Vec<_>>();
    encrypt_result.par_iter().for_each(|ret| {
        if let Err(err) = ret {
            warn!("warning: failed to encrypt file: {err}");
        }
    });
    repo.add_all()?;
    Ok(())
}

pub fn decrypt_repo(repo: &'static Repo, path: Option<impl AsRef<Path>>) -> anyhow::Result<()> {
    assert!(!repo.get_key().is_empty(), "Key must not be empty");

    let pattern = if let Some(path) = path {
        let path = path.as_ref();
        if path.is_dir() {
            format!("{}/*.{ENCRYPTED_EXTENSION}", path.to_path_buf().display(),)
        } else {
            decrypt_file(path, repo.get_key_sha())?;
            repo.add_all()?;
            return Ok(());
        }
    } else {
        format!("*.{ENCRYPTED_EXTENSION}")
    };
    let decrypt_results = repo
        .ls_files_absolute_with_given_patterns(&[pattern.as_str()])?
        .par_iter()
        .filter(|x| x.is_file())
        .map(|f| decrypt_file(f, repo.get_key_sha()))
        .collect::<Vec<_>>();
    decrypt_results.par_iter().for_each(|ret| {
        if let Err(err) = ret {
            warn!("warning: failed to decrypt file: {err}");
        }
    });
    repo.add_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
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
    fn bench_encrypt_file(b: &mut Bencher) {
        let key = calculate_key_sha("602bdc204140db0a".to_owned());
        let key_static = Box::leak(Box::new(key)).as_slice();
        let random_vec = random_vec();
        let tempfile = tempfile::NamedTempFile::new().unwrap();
        let temp_path = tempfile.path();

        b.iter(move || {
            std::fs::write(temp_path, random_vec.as_slice()).unwrap();
            test::black_box(
                encrypt_file(temp_path, key_static, Config::default().zstd_level).unwrap(),
            );
        });
    }
}
