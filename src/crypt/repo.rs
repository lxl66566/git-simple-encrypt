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
        file::{decrypt_file_impl, encrypt_file_impl},
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
        // On a miss, mint the pair but do NOT persist it up front: what
        // belongs in the cache is decided by `encrypt_file_impl` from the
        // run's outcome — the pair actually used on success (so a later
        // external-decrypt → re-encrypt cycle reproduces this exact
        // ciphertext, mirroring the clean filter's first-time writeback),
        // or the real header of an already-encrypted file on skip.
        // Persisting a minted pair up front would leave an entry that
        // diverges from a skipped file's real header. The clean filter can
        // insert before encrypting only because its sniff gate already
        // rejected already-encrypted input before the cache lookup.
        let (salt, file_id) = reader.get(&relative_key).map_or_else(
            || (batch_salt, Some(FileHeader::generate_file_id())),
            |entry| (entry.salt, Some(entry.file_id)),
        );

        get_or_derive_key(&key_cache, key.as_bytes(), &salt)
            .and_then(|derived_key| {
                encrypt_file_impl(
                    f,
                    f,
                    &derived_key,
                    salt,
                    file_id,
                    repo.conf.use_zstd.then_some(repo.conf.zstd_level),
                    Some(CacheRef {
                        sender: &sender,
                        key: &relative_key,
                    }),
                )
            })
            .map_err(|e| with_file_context("encrypt", f, e))
    });

    drop(sender);
    saver.save();

    pb.finish_and_clear();

    report_summary("Encrypt", summary)
}

/// Files per parallel decrypt chunk; also the interval between the first
/// two salt-cache save points.
///
/// Release builds abort on panic without unwinding, so the saver's `Drop`
/// fallback cannot rescue a mid-batch failure. Flushing the entries buffered
/// so far at a save point bounds the loss to the entries since the previous
/// one instead of the whole run (the already-decrypted files stay decrypted
/// — only their re-encryption determinism is at risk).
///
/// Each checkpoint re-serializes the full merged cache, so a fixed interval
/// would make the accumulated rewrite volume grow quadratically with the
/// file count on huge repositories; [`CheckpointSchedule`] doubles the
/// interval after every save point to keep it linear.
const DECRYPT_CHECKPOINT_EVERY: usize = 512;

/// Doubling save-point schedule for batch-decrypt salt-cache checkpoints.
///
/// Save points fire at 512 files, then every doubling of the processed
/// count (1024, 2048, ...). The loss window of a mid-run death therefore
/// grows with the run size instead of staying fixed at one chunk, while the
/// total checkpoint rewrite volume stays proportional to the final cache
/// size rather than quadratic in it.
struct CheckpointSchedule {
    /// File count at which the next save point fires.
    next: usize,
}

impl CheckpointSchedule {
    /// Whether a save point is due after `processed` files; a due check
    /// advances the schedule so the next interval spans twice the processed
    /// count.
    const fn checkpoint_due(&mut self, processed: usize) -> bool {
        if processed < self.next {
            return false;
        }
        self.next = processed.saturating_mul(2);
        true
    }
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
    let (sender, mut saver) = salt_cache::create_writer(repo.path());

    let pb = Progress::new(target_files.len(), "Decrypt");

    let mut summary = BatchSummary {
        total: target_files.len(),
        ..BatchSummary::default()
    };
    let mut schedule = CheckpointSchedule {
        next: DECRYPT_CHECKPOINT_EVERY,
    };
    let mut processed = 0;
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
        processed += chunk.len();
        if schedule.checkpoint_due(processed) {
            saver.checkpoint();
        }
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
    use crate::{
        crypt::{FILE_ID_LEN, derive_key, encrypt_file},
        salt_cache::SaltCacheReader,
    };

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

    #[test]
    fn test_encrypt_repo_records_real_header_of_uncached_encrypted_file() {
        let (_dir, mut repo) = init_repo();
        let file = repo.path().join("f.txt");
        std::fs::write(&file, b"plain").unwrap();
        repo.conf.add_one_path_to_crypt_list("f.txt").unwrap();

        // Simulate a file encrypted by an older build or another machine:
        // a real header on disk, but no cache entry for it. Encrypted with
        // the repo's own compression setting so a later deterministic
        // re-encrypt can be compared byte-for-byte.
        let salt = [0x42; SALT_LEN];
        let file_id = [0x13; FILE_ID_LEN];
        let derived = derive_key(b"test-key", &salt).unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(&*derived);
        let zstd = repo.conf.use_zstd.then_some(repo.conf.zstd_level);
        encrypt_file(&file, &key, &salt, Some(file_id), zstd).unwrap();
        let original_ct = std::fs::read(&file).unwrap();

        // The run skips the file (already encrypted); the writeback must
        // record the file's REAL header — a freshly minted pair would make
        // the next `e` after an external decrypt diverge from the committed
        // blob.
        encrypt_repo(&repo, &[]).unwrap();
        assert_eq!(
            std::fs::read(&file).unwrap(),
            original_ct,
            "must stay untouched"
        );

        let entry = SaltCacheReader::load(repo.path())
            .get(&cache_key(&file, repo.path()))
            .expect("skip must write back the real header");
        assert_eq!(entry.salt, salt);
        assert_eq!(entry.file_id, file_id);

        // The d → e cycle stays deterministic: identical ciphertext.
        decrypt_repo(&repo, &[]).unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"plain");
        encrypt_repo(&repo, &[]).unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), original_ct);
    }

    /// Save points double their interval (512, 1024, 2048, ...): a 20k-file
    /// run fires 6 instead of 39, keeping the accumulated checkpoint rewrite
    /// volume linear in the run size.
    #[test]
    fn test_checkpoint_schedule_doubles_interval() {
        let mut schedule = CheckpointSchedule {
            next: DECRYPT_CHECKPOINT_EVERY,
        };
        assert!(!schedule.checkpoint_due(0));
        assert!(!schedule.checkpoint_due(DECRYPT_CHECKPOINT_EVERY - 1));

        let mut fired = 0;
        let mut processed = 0;
        for _ in 0..20_000 / DECRYPT_CHECKPOINT_EVERY {
            processed += DECRYPT_CHECKPOINT_EVERY;
            if schedule.checkpoint_due(processed) {
                fired += 1;
            }
        }
        // Save points at 512, 1024, 2048, 4096, 8192, 16384.
        assert_eq!(fired, 6);
    }
}
