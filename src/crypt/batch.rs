use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

use dashmap::DashMap;
use rand::Rng;

use crate::{
    crypt::{
        file::{decrypt_file_impl, encrypt_file_to},
        header::SALT_LEN,
        key::{KeyCache, KeyDerivation},
    },
    error::{Error, Result},
    utils::parallel,
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
    pub const fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Decrypt multiple files in parallel, each to a caller-determined destination.
// Test-only until the module goes public (follow-up commit).
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

    parallel::for_each(&sources, |src| {
        // A mapper returning None excludes the file from the batch (counted
        // as skipped so total == succeeded + skipped + failed).
        let Some(dst) = mapper(src) else {
            skipped.fetch_add(1, Ordering::Relaxed);
            return;
        };

        match decrypt_file_impl(
            src,
            &dst,
            master_key,
            KeyDerivation::Shared(&key_cache),
            None,
        ) {
            Ok(Some(_)) => {
                succeeded.fetch_add(1, Ordering::Relaxed);
            },
            Ok(None) => {
                skipped.fetch_add(1, Ordering::Relaxed);
            },
            Err(e) => {
                errors.lock().push((src.clone(), e));
            },
        }
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

    parallel::for_each(&sources, |src| {
        let Some(dst) = mapper(src) else { return };

        match encrypt_file_to(src, &dst, &derived_key, batch_salt, None, zstd) {
            Ok(Some(_)) => {
                succeeded.fetch_add(1, Ordering::Relaxed);
            },
            Ok(None) => {
                skipped.fetch_add(1, Ordering::Relaxed);
            },
            Err(e) => {
                errors.lock().push((src.clone(), e));
            },
        }
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
