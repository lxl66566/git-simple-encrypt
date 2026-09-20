use std::path::{Path, PathBuf};

use dashmap::DashMap;
use fuck_backslash::FuckBackslash;
use log::warn;
use pathdiff::diff_paths;
use rand::prelude::Rng;

use crate::{
    crypt::{
        batch::{BatchSummary, run_batch},
        file::{decrypt_file_impl, encrypt_file},
        header::SALT_LEN,
        key::{KeyCache, KeyDerivation, get_or_derive_key},
    },
    error::{Error, Result},
    repo::Repo,
    salt_cache::{self, CacheRef},
    utils::{Progress, print_post_report, print_pre_report, resolve_target_files},
};

/// Compute a repo-relative cache key from a file path.
///
/// Separators are normalized to `/` (via the same `fuck_backslash` helper the
/// crypt list uses) so the raw-byte key stays consistent across platforms.
#[must_use]
pub fn cache_key(file_path: &Path, repo_path: &Path) -> Vec<u8> {
    let relative = if file_path.is_absolute() {
        diff_paths(file_path, repo_path).unwrap_or_else(|| file_path.to_path_buf())
    } else {
        file_path.to_path_buf()
    };
    relative
        .fuck_backslash()
        .into_os_string()
        .into_encoded_bytes()
}

/// Wrap a per-file failure with the operation and file path for context.
///
/// `AtomicPersist` is passed through unchanged: its `Display` already embeds
/// the destination path, so re-wrapping would print the path twice.
fn with_file_context(action: &str, file: &Path, e: Error) -> Error {
    match e {
        Error::AtomicPersist(..) => e,
        e => Error::Other(format!("Failed to {action} {}: {e}", file.display())),
    }
}

/// Report a completed run: post-report line, every per-file failure logged
/// (messages already embed the file path), and the first failure surfaced as
/// the return value.
fn report_summary(action: &str, summary: BatchSummary) -> Result<()> {
    print_post_report(action, summary.total, summary.skipped, summary.failed);

    for (_, e) in &summary.errors {
        warn!("{e}");
    }
    if let Some((_, first)) = summary.errors.into_iter().next() {
        return Err(first);
    }

    Ok(())
}

/// Encrypt given files in the repo.
pub fn encrypt_repo(repo: &Repo, paths: &[PathBuf]) -> Result<()> {
    let key = repo.get_key()?;
    if key.is_empty() {
        return Err(Error::EmptyKey);
    }

    let target_files = resolve_target_files(paths, &repo.conf.crypt_list, repo.path());
    if target_files.is_empty() {
        return Err(Error::NoFile("encrypt"));
    }

    print_pre_report("Encrypting", &target_files, repo.path());

    let reader = salt_cache::SaltCacheReader::load(repo.path());
    let key_cache: KeyCache = DashMap::new();

    let mut batch_salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut batch_salt);

    let pb = Progress::new(target_files.len(), "Encrypt");

    let summary = run_batch(&target_files, Some(&pb), |f| {
        let relative_key = cache_key(f, repo.path());
        let (salt, cached_file_id) = reader
            .get(&relative_key)
            .map_or((batch_salt, None), |entry| {
                (entry.salt, Some(entry.file_id))
            });

        get_or_derive_key(&key_cache, key.as_bytes(), &salt)
            .and_then(|derived_key| {
                encrypt_file(
                    f,
                    &derived_key,
                    &salt,
                    cached_file_id,
                    repo.conf.use_zstd.then_some(repo.conf.zstd_level),
                )
            })
            .map_err(|e| with_file_context("encrypt", f, e))
    });

    pb.finish_and_clear();

    report_summary("Encrypt", summary)
}

/// Decrypt given files in the repo.
pub fn decrypt_repo(repo: &Repo, paths: &[PathBuf]) -> Result<()> {
    let key = repo.get_key()?;
    if key.is_empty() {
        return Err(Error::EmptyKey);
    }

    let target_files = resolve_target_files(paths, &repo.conf.crypt_list, repo.path());
    if target_files.is_empty() {
        return Err(Error::NoFile("decrypt"));
    }

    print_pre_report("Decrypting", &target_files, repo.path());

    let key_cache: KeyCache = DashMap::new();
    let (sender, saver) = salt_cache::create_writer(repo.path());

    let pb = Progress::new(target_files.len(), "Decrypt");

    let summary = run_batch(&target_files, Some(&pb), |f| {
        let relative_key = cache_key(f, repo.path());

        decrypt_file_impl(
            f,
            f,
            key.as_bytes(),
            KeyDerivation::Shared(&key_cache),
            Some(CacheRef {
                sender: &sender,
                key: &relative_key,
            }),
        )
        .map_err(|e| with_file_context("decrypt", f, e))
    });

    drop(sender);
    saver.save();

    pb.finish_and_clear();

    report_summary("Decrypt", summary)
}
