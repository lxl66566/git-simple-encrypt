use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

use chacha20poly1305::{XChaCha20Poly1305, aead::KeyInit};
use dashmap::DashMap;
use log::debug;
use rand::Rng;
use tempfile::NamedTempFile;
use youpipe::prelude::*;

use crate::{
    crypt::{
        file::{encrypt_file_to, persist_temp_file},
        header::{FileHeader, HEADER_LEN, MAGIC, SALT_LEN, is_encrypted_version},
        key::{KeyCache, get_or_derive_key, split_keys},
        stream::decrypt_body,
    },
    error::{Error, Result},
};

/// Summary of a batch encrypt/decrypt run.
#[derive(Debug, Default)]
pub struct BatchSummary {
    pub total: usize,
    pub succeeded: usize,
    pub skipped: usize,
    pub failed: usize,
    pub errors: Vec<(PathBuf, Error)>,
}

impl BatchSummary {
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Internal: decrypt `src` → `dst` using a shared Argon2 key cache.
#[allow(dead_code)]
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

/// Decrypt multiple files in parallel, each to a caller-determined destination.
#[allow(dead_code, clippy::unnecessary_wraps)]
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

    scope(|s| {
        s.pipe(sources)
            .with_workload(Workload::Unbalanced)
            .map(|src| {
                let Some(dst) = mapper(&src) else { return };

                match decrypt_file_to_with_key_cache(&src, &dst, &key_cache, master_key) {
                    Ok(Some(_)) => {
                        succeeded.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(None) => {
                        skipped.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        errors.lock().push((src, e));
                    }
                }
            })
            .collect()
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
#[allow(dead_code, clippy::unnecessary_wraps)]
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

    let mut batch_salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut batch_salt);
    let derived_key = crate::crypt::key::derive_key(master_key, &batch_salt)?;

    let errors: parking_lot::Mutex<Vec<(PathBuf, Error)>> = parking_lot::Mutex::new(Vec::new());
    let skipped = AtomicUsize::new(0);
    let succeeded = AtomicUsize::new(0);

    scope(|s| {
        s.pipe(sources)
            .with_workload(Workload::Unbalanced)
            .map(|src| {
                let Some(dst) = mapper(&src) else { return };

                match encrypt_file_to(&src, &dst, &derived_key, batch_salt, None, zstd) {
                    Ok(Some(_)) => {
                        succeeded.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(None) => {
                        skipped.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        errors.lock().push((src, e));
                    }
                }
            })
            .collect()
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
