#![no_main]

//! Adversarial bytes as the on-disk salt cache: load, lookups, a locked
//! merge and a reload must never panic.

use std::{path::Path, sync::OnceLock};

use git_simple_encrypt::{
    crypt::{FILE_ID_LEN, SALT_LEN},
    salt_cache::{CachedEntry, SaltCacheReader, merge_entries, resolve_or_insert},
};
use git_simple_encrypt_fuzz::{install_panic_hook, run};
use libfuzzer_sys::fuzz_target;
use tempfile::TempDir;

/// A bare scratch "repo" (just the `.git` directory) per fuzzing process.
fn repo() -> &'static Path {
    static REPO: OnceLock<Box<Path>> = OnceLock::new();
    REPO.get_or_init(|| {
        let dir: &'static TempDir = Box::leak(Box::new(TempDir::new().expect("create temp dir")));
        std::fs::create_dir_all(dir.path().join(".git")).expect("create .git");
        Box::from(dir.path())
    })
}

fuzz_target!(init: install_panic_hook(), |data: &[u8]| {
    run(data, |data| {
        let repo = repo();
        let cache = repo.join(".git").join("git-simple-encrypt-salt-cache");
        std::fs::write(&cache, data).expect("write cache file");

        let reader = SaltCacheReader::load(repo);
        let _ = reader.get(b"a.txt");
        let _ = reader.get(b"FOO/BAR.TXT");
        let _ = reader.get(b"");

        // The locked write path must tolerate an adversarial existing cache
        // too.
        merge_entries(
            repo,
            [(
                b"new.txt".to_vec(),
                CachedEntry {
                    salt: [0xA5; SALT_LEN],
                    file_id: [0x5A; FILE_ID_LEN],
                },
            )],
        );
        let _ = resolve_or_insert(
            repo,
            b"Foo.TXT",
            CachedEntry {
                salt: [0x11; SALT_LEN],
                file_id: [0x22; FILE_ID_LEN],
            },
        );
        let _ = SaltCacheReader::load(repo).get(b"new.txt");

        // Keep the scratch bounded across the run.
        let _ = std::fs::remove_file(&cache);
    });
});
