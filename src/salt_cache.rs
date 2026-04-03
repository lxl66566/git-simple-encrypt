//! Persistent salt+nonce cache for deterministic re-encryption.
//!
//! # Problem
//!
//! Each encryption generates a random salt and nonce, so a decrypt→encrypt
//! cycle on unchanged content produces completely different ciphertext,
//! bloating the git repository.
//!
//! # Solution
//!
//! During **decrypt**, the file's salt and nonce are captured. During
//! **encrypt**, the cached values are reused so that decrypt→encrypt on the
//! same plaintext produces byte-identical output.
//!
//! # Thread Safety
//!
//! Internally backed by [`DashMap`], supporting non-blocking concurrent reads
//! and writes from multiple threads (e.g. rayon worker threads).
//!
//! # Persistence
//!
//! Serialized via [`bincode`] to `<repo>/.git/git-simple-encrypt-salt-cache`
//! for maximum performance. The binary format is opaque and not meant for human
//! consumption.
//!
//! # Lifecycle
//!
//! - **Decrypt**: Load → populate with extracted (salt, nonce) → save
//! - **Encrypt**: Load → use cached entries → save (with any new entries)
//! - **On error**: Cache is saved with whatever entries were captured before
//!   the failure, preserving partial progress.
//! - **After encrypt**: Cache is **not** deleted. It persists for the next
//!   decrypt→encrypt cycle.
//! - **Stale entries**: Entries for files that no longer exist are harmless
//!   (looked up by path, simply not found) and do not affect correctness.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use dashmap::DashMap;
use fuck_backslash::FuckBackslash;
use log::{debug, warn};
use serde::{Deserialize, Serialize};

/// File name for the persistent salt cache, stored inside `.git/`.
const CACHE_FILENAME: &str = "git-simple-encrypt-salt-cache";

/// Salt size in bytes — must match [`crate::crypt::SALT_LEN`].
const SALT_LEN: usize = 16;
/// Nonce size in bytes — must match [`crate::crypt::NONCE_LEN`].
const NONCE_LEN: usize = 24;

/// A cached header entry for deterministic re-encryption.
///
/// Stores the salt (for key derivation) and base nonce (for chunk nonces) so
/// that re-encrypting the same plaintext produces byte-identical ciphertext.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CachedEntry {
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
}

/// Thread-safe salt cache that persists `file path → (salt, nonce)` mappings.
///
/// See [module-level documentation](self) for the full design rationale.
pub struct SaltCache {
    inner: DashMap<PathBuf, CachedEntry>,
    cache_path: PathBuf,
    repo_path: PathBuf,
}

impl SaltCache {
    /// Load the salt cache for the given repository.
    ///
    /// If the cache file does not exist or is corrupted, returns an empty
    /// cache. This never fails — a missing or corrupt cache simply means we
    /// start fresh (new salts will be generated during encryption).
    pub fn load(repo_path: &Path) -> Self {
        let cache_path = repo_path.join(".git").join(CACHE_FILENAME);
        let this = Self {
            inner: DashMap::new(),
            cache_path,
            repo_path: repo_path.to_path_buf(),
        };

        if !this.cache_path.exists() {
            debug!(
                "Salt cache not found at {}, starting fresh",
                this.cache_path.display()
            );
            return this;
        }

        match std::fs::read(&this.cache_path) {
            Ok(data) => match bincode::deserialize::<HashMap<PathBuf, CachedEntry>>(&data) {
                Ok(entries) => {
                    let count = entries.len();
                    for (path, entry) in entries {
                        this.inner.insert(path, entry);
                    }
                    debug!(
                        "Loaded salt cache with {count} entries from {}",
                        this.cache_path.display()
                    );
                    this
                }
                Err(e) => {
                    warn!(
                        "Corrupted salt cache at {}, starting fresh: {e}",
                        this.cache_path.display()
                    );
                    this
                }
            },
            Err(e) => {
                warn!(
                    "Failed to read salt cache at {}: {e}",
                    this.cache_path.display()
                );
                this
            }
        }
    }

    /// Save the salt cache to disk (best-effort).
    ///
    /// Errors are logged but not propagated because cache persistence is
    /// non-critical: losing the cache only means the next encryption uses
    /// fresh salts.
    pub fn save(&self) {
        // Collect DashMap entries into a plain HashMap for serialization.
        let entries: HashMap<PathBuf, CachedEntry> = self
            .inner
            .iter()
            .map(|r| (r.key().clone(), r.value().clone()))
            .collect();

        match bincode::serialize(&entries) {
            Ok(data) => {
                if let Err(e) = std::fs::write(&self.cache_path, data) {
                    warn!(
                        "Failed to save salt cache to {}: {e}",
                        self.cache_path.display()
                    );
                } else {
                    debug!(
                        "Saved salt cache with {} entries to {}",
                        entries.len(),
                        self.cache_path.display()
                    );
                }
            }
            Err(e) => {
                warn!("Failed to serialize salt cache: {e}");
            }
        }
    }

    /// Convert an absolute file path to a repo-relative path for use as a
    /// cache key. This ensures portability when the repo is moved.
    fn to_relative_key(&self, abs_path: &Path) -> PathBuf {
        pathdiff::diff_paths(abs_path, &self.repo_path)
            .unwrap_or_else(|| abs_path.to_path_buf())
            .fuck_backslash()
    }

    /// Insert or update a cache entry for the given file (absolute path).
    pub fn insert(&self, abs_path: &Path, entry: CachedEntry) {
        let key = self.to_relative_key(abs_path);
        self.inner.insert(key, entry);
    }

    /// Retrieve a cached entry for the given file (absolute path).
    pub fn get(&self, abs_path: &Path) -> Option<CachedEntry> {
        let key = self.to_relative_key(abs_path);
        self.inner.get(&key).map(|r| r.value().clone())
    }

    /// Returns the number of entries in the cache (for testing).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn make_entry(salt_byte: u8, nonce_byte: u8) -> CachedEntry {
        CachedEntry {
            salt: [salt_byte; SALT_LEN],
            nonce: [nonce_byte; NONCE_LEN],
        }
    }

    #[test]
    fn test_insert_and_get() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        let cache = SaltCache::load(repo);

        let file_path = repo.join("test.txt");
        let entry = make_entry(0xAA, 0xBB);
        cache.insert(&file_path, entry.clone());

        assert_eq!(cache.get(&file_path), Some(entry));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_get_missing_returns_none() {
        let dir = TempDir::new().unwrap();
        let cache = SaltCache::load(dir.path());
        assert_eq!(cache.get(&dir.path().join("nonexistent.txt")), None);
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let entry1 = make_entry(0x11, 0x22);
        let entry2 = make_entry(0x33, 0x44);

        {
            let cache = SaltCache::load(repo);
            cache.insert(&repo.join("file1.txt"), entry1.clone());
            cache.insert(&repo.join("sub/file2.txt"), entry2.clone());
            cache.save();
        }

        // Load again from disk and verify.
        let cache = SaltCache::load(repo);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(&repo.join("file1.txt")), Some(entry1));
        assert_eq!(cache.get(&repo.join("sub/file2.txt")), Some(entry2));
    }

    #[test]
    fn test_load_corrupted_file() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let cache_path = repo.join(".git").join(CACHE_FILENAME);
        std::fs::write(&cache_path, b"not valid bincode data").unwrap();

        // Should return an empty cache without panicking.
        let cache = SaltCache::load(repo);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_load_missing_file() {
        let dir = TempDir::new().unwrap();
        let cache = SaltCache::load(dir.path());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_overwrite_entry() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        let cache = SaltCache::load(repo);

        let file_path = repo.join("test.txt");
        let entry1 = make_entry(0x11, 0x22);
        let entry2 = make_entry(0x33, 0x44);

        cache.insert(&file_path, entry1);
        cache.insert(&file_path, entry2.clone());

        assert_eq!(cache.get(&file_path), Some(entry2));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_relative_path_key_persistence() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let abs_path = repo.join("subdir").join("file.txt");
        let entry = make_entry(0x55, 0x66);

        {
            let cache = SaltCache::load(repo);
            cache.insert(&abs_path, entry.clone());
            cache.save();
        }

        // Reload and verify the entry is still accessible via the same
        // absolute path.
        let loaded = SaltCache::load(repo);
        assert_eq!(loaded.get(&abs_path), Some(entry));
    }
}
