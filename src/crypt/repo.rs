use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

use dashmap::DashMap;
use pathdiff::diff_paths;
use rand::prelude::*;
use youpipe::prelude::*;

use crate::{
    crypt::{
        file::{decrypt_file_with_cache, encrypt_file},
        header::SALT_LEN,
        key::{KeyCache, get_or_derive_key},
    },
    error::{Error, Result},
    repo::Repo,
    salt_cache::{self, CacheRef},
    utils::{
        Progress, is_file_encrypted, print_post_report, print_pre_report, resolve_target_files,
    },
};

/// Compute a repo-relative cache key from a file path.
#[must_use]
pub fn cache_key(file_path: &Path, repo_path: &Path) -> Vec<u8> {
    let relative = if file_path.is_absolute() {
        diff_paths(file_path, repo_path).unwrap_or_else(|| file_path.to_path_buf())
    } else {
        file_path.to_path_buf()
    };
    let mut bytes = relative.into_os_string().into_encoded_bytes();
    for b in &mut bytes {
        if *b == b'\\' {
            *b = b'/';
        }
    }
    bytes
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

    let total = target_files.len();
    let pb = Progress::new(total, "Encrypt");
    let skipped = AtomicUsize::new(0);
    let failed = AtomicUsize::new(0);

    let result = {
        let errors: parking_lot::Mutex<Vec<Error>> = parking_lot::Mutex::new(Vec::new());
        scope(|s| {
            s.pipe(target_files)
                .with_workload(Workload::Unbalanced)
                .map(|f| {
                    let relative_key = cache_key(&f, repo.path());
                    let (salt, cached_file_id) = reader
                        .get(&relative_key)
                        .map_or((batch_salt, None), |entry| {
                            (entry.salt, Some(entry.file_id))
                        });

                    let derived_key = match get_or_derive_key(&key_cache, key.as_bytes(), &salt) {
                        Ok(k) => k,
                        Err(e) => {
                            failed.fetch_add(1, Ordering::Relaxed);
                            errors.lock().push(e);
                            pb.inc(1);
                            return;
                        }
                    };

                    let r = encrypt_file(
                        &f,
                        &derived_key,
                        &salt,
                        cached_file_id,
                        repo.conf.use_zstd.then_some(repo.conf.zstd_level),
                    )
                    .map_err(|e| Error::Other(format!("Failed to encrypt {}: {e}", f.display())));

                    match r {
                        Ok(Some(_)) => {}
                        Ok(None) => {
                            skipped.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            failed.fetch_add(1, Ordering::Relaxed);
                            errors.lock().push(e);
                        }
                    }

                    pb.inc(1);
                })
                .collect()
        });
        errors.into_inner()
    };

    pb.finish_and_clear();

    print_post_report(
        "Encrypt",
        total,
        skipped.load(Ordering::Relaxed),
        failed.load(Ordering::Relaxed),
    );

    if let Some(first) = result.into_iter().next() {
        return Err(first);
    }

    Ok(())
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

    let total = target_files.len();
    let pb = Progress::new(total, "Decrypt");
    let skipped = AtomicUsize::new(0);
    let failed = AtomicUsize::new(0);

    let result = {
        let errors: parking_lot::Mutex<Vec<Error>> = parking_lot::Mutex::new(Vec::new());
        scope(|s| {
            s.pipe(target_files)
                .with_workload(Workload::Unbalanced)
                .map(|f| {
                    match is_file_encrypted(&f) {
                        Ok(true) => {}
                        Ok(false) => {
                            skipped.fetch_add(1, Ordering::Relaxed);
                            pb.inc(1);
                            return;
                        }
                        Err(e) => {
                            failed.fetch_add(1, Ordering::Relaxed);
                            errors.lock().push(e);
                            pb.inc(1);
                            return;
                        }
                    }

                    let relative_key = cache_key(&f, repo.path());

                    let r = decrypt_file_with_cache(
                        &f,
                        &key_cache,
                        Some(CacheRef {
                            sender: &sender,
                            key: &relative_key,
                        }),
                        key.as_bytes(),
                    )
                    .map_err(|e| Error::Other(format!("Failed to decrypt {}: {e}", f.display())));

                    if let Err(e) = r {
                        failed.fetch_add(1, Ordering::Relaxed);
                        errors.lock().push(e);
                    }

                    pb.inc(1);
                })
                .collect()
        });
        errors.into_inner()
    };

    drop(sender);
    saver.save();

    pb.finish_and_clear();

    print_post_report(
        "Decrypt",
        total,
        skipped.load(Ordering::Relaxed),
        failed.load(Ordering::Relaxed),
    );

    if let Some(first) = result.into_iter().next() {
        return Err(first);
    }

    Ok(())
}
