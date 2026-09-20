//! Parallel batch encrypt/decrypt with a shared Argon2 key cache.
//!
//! Also hosts the crate-internal `run_batch` engine behind the batch entry
//! points and `encrypt_repo`/`decrypt_repo` (SMELL-2: one definition of the
//! succeeded/skipped/failed accounting instead of per-caller hand-rolled
//! counters).

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
    utils::{Progress, parallel},
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

/// Run `op` over `files` in parallel and tally per-file outcomes into a
/// [`BatchSummary`].
///
/// Outcome mapping: `Ok(Some(_))` counts as succeeded, `Ok(None)` as skipped,
/// `Err` as failed and is recorded with its file path. `progress`, when given,
/// is advanced exactly once per file regardless of outcome.
pub(super) fn run_batch<T, F>(files: &[PathBuf], progress: Option<&Progress>, op: F) -> BatchSummary
where
    F: Fn(&Path) -> Result<Option<T>> + Sync,
{
    let succeeded = AtomicUsize::new(0);
    let skipped = AtomicUsize::new(0);
    let errors: parking_lot::Mutex<Vec<(PathBuf, Error)>> = parking_lot::Mutex::new(Vec::new());

    parallel::for_each(files, |path| {
        match op(path) {
            Ok(Some(_)) => {
                succeeded.fetch_add(1, Ordering::Relaxed);
            },
            Ok(None) => {
                skipped.fetch_add(1, Ordering::Relaxed);
            },
            Err(e) => {
                errors.lock().push((path.clone(), e));
            },
        }
        if let Some(pb) = progress {
            pb.inc(1);
        }
    });

    let errors = errors.into_inner();
    BatchSummary {
        total: files.len(),
        succeeded: succeeded.load(Ordering::Relaxed),
        skipped: skipped.load(Ordering::Relaxed),
        failed: errors.len(),
        errors,
    }
}

/// Decrypt multiple files in parallel, each to a caller-determined destination.
///
/// Files that are not encrypted by this tool are skipped; a `mapper` returning
/// `None` excludes its file from the run and also counts as skipped, so
/// `total == succeeded + skipped + failed` always holds.
pub fn decrypt_files_to<I, P, F>(sources: I, master_key: &[u8], mapper: F) -> BatchSummary
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path> + Sync,
    F: Fn(&Path) -> Option<PathBuf> + Sync,
{
    let sources: Vec<PathBuf> = sources
        .into_iter()
        .map(|p| p.as_ref().to_path_buf())
        .collect();

    let key_cache: KeyCache = DashMap::new();
    run_batch(&sources, None, |src| {
        let Some(dst) = mapper(src) else {
            return Ok(None);
        };
        decrypt_file_impl(
            src,
            &dst,
            master_key,
            KeyDerivation::Shared(&key_cache),
            None,
        )
    })
}

/// Encrypt multiple files in parallel, each from a caller-determined source to
/// a caller-determined destination.
///
/// All files share one random salt and Argon2-derived key for the whole batch;
/// `mapper` returning `None` counts as skipped, mirroring
/// [`decrypt_files_to`].
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

    let mut batch_salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut batch_salt);
    let derived_key = crate::crypt::key::derive_key(master_key, &batch_salt)?;

    Ok(run_batch(&sources, None, |src| {
        let Some(dst) = mapper(src) else {
            return Ok(None);
        };
        encrypt_file_to(src, &dst, &derived_key, batch_salt, None, zstd)
    }))
}
