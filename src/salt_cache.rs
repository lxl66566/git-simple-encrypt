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
//! # Architecture
//!
//! ## Read Path (encrypt) — Zero-copy via mmap + rkyv
//!
//! [`SaltCacheReader`] memory-maps the cache file and uses rkyv's zero-copy
//! deserialization to access the archived `HashMap<String, CachedEntry>`
//! directly. No heap allocation or full deserialization is required for
//! lookups.
//!
//! ## Write Path (encrypt/decrypt) — mpsc + rkyv
//!
//! [`SaltCacheSender`] is a `Sync` handle that wraps an `mpsc::Sender`.
//! Rayon worker threads send `(path, entry)` pairs through the channel.
//! After all parallel work completes, [`SaltCacheSaver`] collects the
//! entries, merges with any existing on-disk cache, and serializes the
//! result via rkyv.
//!
//! # Persistence
//!
//! Serialized via [`rkyv`] to `<repo>/.git/git-simple-encrypt-salt-cache`.
//! The binary format is opaque and not meant for human consumption.
//!
//! # Lifecycle
//!
//! - **Decrypt**: Create sender → workers send entries → saver persists
//! - **Encrypt**: Create reader (mmap) + sender → workers read/write → saver
//!   persists (merges with existing)
//! - **On error**: Cache is saved with whatever entries were captured before
//!   the failure, preserving partial progress.
//! - **Stale entries**: Entries for files that no longer exist are harmless
//!   (looked up by path, simply not found) and do not affect correctness.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::mpsc,
};

use fuck_backslash::FuckBackslash;
use log::{debug, warn};
use memmap2::Mmap;
use rkyv::rancor::Error as RkyvError;

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
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CachedEntry {
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
}

/// Convert an absolute file path to a repo-relative string for use as a
/// cache key. This ensures portability when the repo is moved.
fn to_relative_key(abs_path: &Path, repo_path: &Path) -> String {
    pathdiff::diff_paths(abs_path, repo_path)
        .unwrap_or_else(|| abs_path.to_path_buf())
        .fuck_backslash()
        .to_string_lossy()
        .into_owned()
}

/// Returns the cache file path for the given repo.
fn cache_path(repo_path: &Path) -> PathBuf {
    repo_path.join(".git").join(CACHE_FILENAME)
}

// ---------------------------------------------------------------------------
// Read Path — zero-copy via mmap + rkyv
// ---------------------------------------------------------------------------

/// Read-only salt cache backed by memory-mapped file + rkyv zero-copy access.
///
/// Used during **encryption** to look up previously cached salt/nonce values
/// without allocating or fully deserializing the cache.
///
/// This type is `Sync` and safe to share across rayon worker threads via
/// `&self` references.
pub struct SaltCacheReader {
    /// The memory-mapped cache file. `None` if no cache exists.
    mmap: Option<Mmap>,
    repo_path: PathBuf,
}

impl SaltCacheReader {
    /// Open the salt cache for the given repository.
    ///
    /// If the cache file does not exist or is corrupted, returns an empty
    /// reader (all lookups will return `None`). This never fails — a missing
    /// or corrupt cache simply means we start fresh (new salts will be
    /// generated during encryption).
    pub fn load(repo_path: &Path) -> Self {
        let path = cache_path(repo_path);

        let mmap = if path.exists() {
            match std::fs::File::open(&path) {
                Ok(file) => match unsafe { Mmap::map(&file) } {
                    Ok(mmap) => {
                        // Validate the archived data on load so that
                        // `access_unchecked` in `get()` is sound.
                        match rkyv::access::<rkyv::Archived<HashMap<String, CachedEntry>>, RkyvError>(
                            &mmap,
                        ) {
                            Ok(_) => {
                                debug!("Loaded salt cache from {}", path.display());
                                Some(mmap)
                            }
                            Err(e) => {
                                warn!("Corrupted salt cache at {}: {e}", path.display());
                                None
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to mmap salt cache at {}: {e}", path.display());
                        None
                    }
                },
                Err(e) => {
                    warn!("Failed to open salt cache at {}: {e}", path.display());
                    None
                }
            }
        } else {
            debug!("Salt cache not found at {}", path.display());
            None
        };

        Self {
            mmap,
            repo_path: repo_path.to_path_buf(),
        }
    }

    /// Look up a cached entry by absolute file path. Zero-copy.
    ///
    /// Returns `None` if no cache file exists or the path is not cached.
    pub fn get(&self, abs_path: &Path) -> Option<CachedEntry> {
        let mmap = self.mmap.as_ref()?;

        // SAFETY: We validated the mmap data in `load()`. The mapped file is
        // not modified while this reader is alive (only git-se touches the
        // cache, and we hold it open).
        let archived = unsafe {
            rkyv::access_unchecked::<rkyv::Archived<HashMap<String, CachedEntry>>>(mmap.as_ref())
        };

        let key = to_relative_key(abs_path, &self.repo_path);
        let entry = archived.get(key.as_str())?;

        // For [u8; N] fields, Archived<[u8; N]> = [u8; N], so we can copy
        // directly.
        Some(CachedEntry {
            salt: entry.salt,
            nonce: entry.nonce,
        })
    }
}

// ---------------------------------------------------------------------------
// Write Path — mpsc collection + rkyv serialization
// ---------------------------------------------------------------------------

/// Thread-safe sender for cache entries, safe to share across rayon workers.
///
/// Workers call [`insert`](Self::insert) to send `(path, entry)` pairs
/// through an internal `mpsc` channel. After all parallel work completes,
/// the paired [`SaltCacheSaver`] collects and persists the entries.
pub struct SaltCacheSender {
    tx: mpsc::Sender<(String, CachedEntry)>,
    repo_path: PathBuf,
}

impl SaltCacheSender {
    /// Send a cache entry for the given file (absolute path).
    ///
    /// This is thread-safe (`&Self`) and non-blocking. Errors (e.g. channel
    /// closed) are silently ignored because cache persistence is non-critical.
    pub fn insert(&self, abs_path: &Path, entry: CachedEntry) {
        let key = to_relative_key(abs_path, &self.repo_path);
        let _ = self.tx.send((key, entry));
    }
}

/// Receiver that collects and persists cache entries to disk.
///
/// Created paired with a [`SaltCacheSender`] via [`create_writer`]. After all
/// parallel work completes, call [`save`](Self::save) to collect entries,
/// merge with any existing on-disk cache, and serialize via rkyv.
///
/// This type is **not** `Sync` — it should only be used on the main thread
/// after rayon work completes.
pub struct SaltCacheSaver {
    rx: mpsc::Receiver<(String, CachedEntry)>,
    repo_path: PathBuf,
}

impl SaltCacheSaver {
    /// Persist all collected entries to disk (best-effort).
    ///
    /// 1. Drops the internal sender (via the paired `SaltCacheSender` going out
    ///    of scope in the caller) so the channel closes.
    /// 2. Collects all `(path, entry)` pairs from the channel.
    /// 3. Merges with any existing on-disk cache (existing entries are kept
    ///    only if no new entry overrides them).
    /// 4. Serializes via rkyv and writes to `<repo>/.git/<CACHE_FILENAME>`.
    ///
    /// Errors are logged but not propagated because cache persistence is
    /// non-critical: losing the cache only means the next encryption uses
    /// fresh salts.
    pub fn save(self) {
        let Self { rx, repo_path } = self;

        // Collect all entries sent through the channel. The sender side must
        // have been dropped (or going to be dropped) by the caller before
        // this call, otherwise `into_iter()` will block.
        let mut entries: HashMap<String, CachedEntry> = rx.into_iter().collect();

        // Merge with existing cache on disk (keep existing entries only when
        // no new entry covers the same path).
        let path = cache_path(&repo_path);
        if path.exists()
            && let Ok(existing_bytes) = std::fs::read(&path)
            && let Ok(existing) =
                rkyv::from_bytes::<HashMap<String, CachedEntry>, RkyvError>(&existing_bytes)
        {
            for (k, v) in existing {
                entries.entry(k).or_insert(v);
            }
        }

        // Serialize and write.
        match rkyv::to_bytes::<RkyvError>(&entries) {
            Ok(bytes) => {
                if let Err(e) = std::fs::write(&path, bytes.as_slice()) {
                    warn!("Failed to save salt cache to {}: {e}", path.display());
                } else {
                    debug!(
                        "Saved salt cache with {} entries to {}",
                        entries.len(),
                        path.display()
                    );
                }
            }
            Err(e) => {
                warn!("Failed to serialize salt cache: {e}");
            }
        }
    }
}

/// Create a paired sender/saver for collecting cache entries.
///
/// The sender is `Sync` and can be shared across rayon threads. The saver
/// should be kept on the main thread and `.save()`d after parallel work
/// completes.
pub fn create_writer(repo_path: &Path) -> (SaltCacheSender, SaltCacheSaver) {
    let (tx, rx) = mpsc::channel();
    let repo_path = repo_path.to_path_buf();
    (
        SaltCacheSender {
            tx,
            repo_path: repo_path.clone(),
        },
        SaltCacheSaver { rx, repo_path },
    )
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
    fn test_reader_get_from_empty() {
        let dir = TempDir::new().unwrap();
        let reader = SaltCacheReader::load(dir.path());
        assert_eq!(reader.get(&dir.path().join("test.txt")), None);
    }

    #[test]
    fn test_roundtrip_via_sender_and_reader() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let entry1 = make_entry(0x11, 0x22);
        let entry2 = make_entry(0x33, 0x44);

        {
            let (sender, saver) = create_writer(repo);
            sender.insert(&repo.join("file1.txt"), entry1.clone());
            sender.insert(&repo.join("sub/file2.txt"), entry2.clone());
            // Drop sender to close the channel before saving.
            drop(sender);
            saver.save();
        }

        // Load via reader and verify.
        let reader = SaltCacheReader::load(repo);
        assert_eq!(reader.get(&repo.join("file1.txt")), Some(entry1));
        assert_eq!(reader.get(&repo.join("sub/file2.txt")), Some(entry2));
        assert_eq!(reader.get(&repo.join("nonexistent.txt")), None);
    }

    #[test]
    fn test_load_corrupted_file() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let path = cache_path(repo);
        std::fs::write(&path, b"not valid rkyv data").unwrap();

        // Should return a reader with no data (all lookups return None).
        let reader = SaltCacheReader::load(repo);
        assert_eq!(reader.get(&repo.join("test.txt")), None);
    }

    #[test]
    fn test_load_missing_file() {
        let dir = TempDir::new().unwrap();
        let reader = SaltCacheReader::load(dir.path());
        assert_eq!(reader.get(&dir.path().join("test.txt")), None);
    }

    #[test]
    fn test_overwrite_entry() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let entry1 = make_entry(0x11, 0x22);
        let entry2 = make_entry(0x33, 0x44);

        {
            let (sender, saver) = create_writer(repo);
            sender.insert(&repo.join("test.txt"), entry1);
            sender.insert(&repo.join("test.txt"), entry2.clone());
            drop(sender);
            saver.save();
        }

        let reader = SaltCacheReader::load(repo);
        assert_eq!(reader.get(&repo.join("test.txt")), Some(entry2));
    }

    #[test]
    fn test_relative_path_key_persistence() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let abs_path = repo.join("subdir").join("file.txt");
        let entry = make_entry(0x55, 0x66);

        {
            let (sender, saver) = create_writer(repo);
            sender.insert(&abs_path, entry.clone());
            drop(sender);
            saver.save();
        }

        let reader = SaltCacheReader::load(repo);
        assert_eq!(reader.get(&abs_path), Some(entry));
    }

    #[test]
    fn test_merge_with_existing() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let entry_a = make_entry(0xAA, 0xBB);
        let entry_b = make_entry(0xCC, 0xDD);

        // Save initial entry.
        {
            let (sender, saver) = create_writer(repo);
            sender.insert(&repo.join("existing.txt"), entry_a.clone());
            drop(sender);
            saver.save();
        }

        // Save a new entry — the existing one should be preserved via merge.
        {
            let (sender, saver) = create_writer(repo);
            sender.insert(&repo.join("new.txt"), entry_b.clone());
            drop(sender);
            saver.save();
        }

        let reader = SaltCacheReader::load(repo);
        assert_eq!(reader.get(&repo.join("existing.txt")), Some(entry_a));
        assert_eq!(reader.get(&repo.join("new.txt")), Some(entry_b));
    }
}
