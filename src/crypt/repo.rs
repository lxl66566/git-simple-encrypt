use std::path::{Path, PathBuf};

use dashmap::DashMap;
use fuck_backslash::FuckBackslash;
use log::warn;
use pathdiff::diff_paths;
use rand::prelude::Rng;

use crate::{
    crypt::{
        FileHeader,
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
    let (sender, saver) = salt_cache::create_writer(repo.path());
    let key_cache: KeyCache = DashMap::new();

    let mut batch_salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut batch_salt);

    let pb = Progress::new(target_files.len(), "Encrypt");

    let summary = run_batch(&target_files, Some(&pb), |f| {
        let relative_key = cache_key(f, repo.path());
        let (salt, file_id) = reader.get(&relative_key).map_or_else(
            || {
                // Fresh entry: mint a file_id up front and record the pair, so
                // a later external-decrypt → re-encrypt cycle reproduces this
                // exact ciphertext (mirrors what the clean filter does for
                // first-time files; without the writeback the file_id would
                // change every time the plaintext reappears, surfacing as a
                // one-time phantom modification).
                let file_id = FileHeader::generate_file_id();
                sender.insert(&relative_key, salt_cache::CachedEntry {
                    salt: batch_salt,
                    file_id,
                });
                (batch_salt, Some(file_id))
            },
            |entry| (entry.salt, Some(entry.file_id)),
        );

        get_or_derive_key(&key_cache, key.as_bytes(), &salt)
            .and_then(|derived_key| {
                encrypt_file(
                    f,
                    &derived_key,
                    &salt,
                    file_id,
                    repo.conf.use_zstd.then_some(repo.conf.zstd_level),
                )
            })
            .map_err(|e| with_file_context("encrypt", f, e))
    });

    drop(sender);
    saver.save();

    pb.finish_and_clear();

    report_summary("Encrypt", summary)
}

/// How many files a batch decrypt processes between salt-cache save points.
///
/// Release builds abort on panic without unwinding, so the saver's `Drop`
/// fallback cannot rescue a mid-batch failure. Flushing the entries buffered
/// so far after every chunk bounds the loss to one chunk of cache entries
/// instead of the whole run (the already-decrypted files stay decrypted —
/// only their re-encryption determinism is at risk). 512 balances flush
/// overhead (one locked cache read+write per chunk) against the loss window.
const DECRYPT_CHECKPOINT_EVERY: usize = 512;

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
    let (sender, mut saver) = salt_cache::create_writer(repo.path());

    let pb = Progress::new(target_files.len(), "Decrypt");

    let mut summary = BatchSummary {
        total: target_files.len(),
        ..BatchSummary::default()
    };
    for chunk in target_files.chunks(DECRYPT_CHECKPOINT_EVERY) {
        let part = run_batch(chunk, Some(&pb), |f| {
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
        summary.succeeded += part.succeeded;
        summary.skipped += part.skipped;
        summary.errors.extend(part.errors);
        saver.checkpoint();
    }
    summary.failed = summary.errors.len();

    drop(sender);
    saver.save();

    pb.finish_and_clear();

    report_summary("Decrypt", summary)
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use path_absolutize::Absolutize;
    use tempfile::TempDir;

    use super::*;

    fn init_repo() -> (TempDir, Repo) {
        let dir = TempDir::new().unwrap();
        Command::new("git")
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        let repo_path = dir.path().absolutize().unwrap().to_path_buf();
        let repo = Repo::open(&repo_path).unwrap();
        repo.set_config("key", "test-key").unwrap();
        (dir, repo)
    }

    #[test]
    fn test_encrypt_repo_writes_back_fresh_entries() {
        let (_dir, mut repo) = init_repo();
        std::fs::write(repo.path().join("f.txt"), b"plain").unwrap();
        repo.conf.add_one_path_to_crypt_list("f.txt").unwrap();

        encrypt_repo(&repo, &[]).unwrap();
        let ct1 = std::fs::read(repo.path().join("f.txt")).unwrap();

        // Simulate an external restore of the plaintext (never went through
        // our decrypt, so the cache is the only memory of the file): without
        // the encrypt-side writeback the second run would mint a new
        // file_id and produce different ciphertext (phantom modification).
        std::fs::write(repo.path().join("f.txt"), b"plain").unwrap();
        encrypt_repo(&repo, &[]).unwrap();
        let ct2 = std::fs::read(repo.path().join("f.txt")).unwrap();

        assert_eq!(ct1, ct2);
    }
}
