//! Persistent `salt+file_id` cache for deterministic re-encryption.
//!
//! During **decrypt**, the file's salt and `file_id` are recorded. During
//! **encrypt**, the cached values are reused so that decrypt→encrypt on the
//! same plaintext produces byte-identical output.
//!
//! # Architecture
//!
//! ## Read Path (encrypt) — one-shot read + rkyv
//!
//! [`SaltCacheReader`] reads the whole cache file into memory once and
//! deserializes it via rkyv. It used to mmap the file for zero-copy lookups,
//! but on Windows an active mapping blocks the rename that atomically
//! replaces the cache, so a reader could make every concurrent cache write
//! (including its own process's) fail with access-denied. The cache is tiny —
//! tens of bytes per tracked file — so a plain read costs nothing and removes
//! the hazard entirely.
//!
//! ## Write Path (decrypt) — mpsc + rkyv
//!
//! [`SaltCacheSender`] is a `Sync` handle that wraps an `mpsc::Sender`.
//! Worker threads send `(path, entry)` pairs through the channel. After all
//! parallel work completes, [`SaltCacheSaver`] collects the entries, merges
//! with any existing on-disk cache, and serializes the result via rkyv.
//!
//! ## Single-Writer Lock Protocol
//!
//! All mutations — the filter drivers' per-file merges ([`merge_entries`],
//! [`resolve_or_insert`]) and the batch saver's checkpoints/final save — run
//! under an exclusive OS lock on `<cache>.lock`, so concurrent processes
//! cannot lose each other's entries.
//!
//! # Key Format
//!
//! Cache keys are repo-relative path bytes with forward slashes (`b'/'`),
//! computed by the caller via [`crate::crypt::cache_key`]. Using raw bytes
//! (`Vec<u8>`) avoids UTF-8 validation overhead and string allocation. On
//! case-insensitive filesystems (Windows, macOS) keys are stored
//! ASCII-lowercased; see [`storage_key`] for the compatibility story.
//!
//! # Persistence
//!
//! Serialized via [`rkyv`] to the repo's real git directory (resolving the
//! `gitdir:` pointer of linked worktrees/submodules, see [`resolve_git_dir`]):
//! `<gitdir>/git-simple-encrypt-salt-cache`. The binary format is opaque and
//! not meant for human consumption. Writes are performed atomically to
//! prevent corruption, and skipped when nothing changed (see [`write_merged`]).
//!
//! # Lifecycle
//!
//! - **Decrypt**: Create sender → workers send entries → saver persists (atomically), with periodic
//!   [`SaltCacheSaver::checkpoint`]s during long batches.
//! - **Encrypt**: Create a reader (read-only) → workers look up cached values. The cache is written
//!   during encryption only when a fresh entry is minted ([`resolve_or_insert`]; manual
//!   `encrypt_repo` writes back through the sender/saver pair).
//! - **On error**: The cache is saved with whatever entries were captured before the failure,
//!   preserving partial progress.
//! - **Stale entries**: Entries for files that no longer exist are harmless (looked up by key,
//!   simply not found) and do not affect correctness.

use std::{
    borrow::Cow,
    collections::HashMap,
    fmt,
    path::{Path, PathBuf},
    sync::mpsc,
};

use log::{debug, error, warn};
use rkyv::rancor::Error as RkyvError;

use crate::{
    crypt::{FILE_ID_LEN, SALT_LEN},
    utils::atomic_write,
};

/// File name for the persistent salt cache, stored inside `.git/`.
const CACHE_FILENAME: &str = "git-simple-encrypt-salt-cache";

/// A cached header entry for deterministic re-encryption.
///
/// Stores the salt (for key derivation) and `file_id` (for nonce derivation) so
/// that re-encrypting the same plaintext produces byte-identical ciphertext.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CachedEntry {
    pub salt: [u8; SALT_LEN],
    pub file_id: [u8; FILE_ID_LEN],
}

/// Borrowed reference to a salt-cache writer + the repo-relative key for a
/// single file.
///
/// Passed into [`crate::crypt::decrypt_file_with_cache`] so that the decrypt
/// path can record `(salt, file_id)` for deterministic re-encryption.
#[derive(Clone, Copy)]
pub struct CacheRef<'a> {
    /// The thread-safe sender that forwards entries to the persister thread.
    pub sender: &'a SaltCacheSender,
    /// Forward-slash-normalized repo-relative path bytes for this file.
    pub key: &'a [u8],
}

impl fmt::Debug for CacheRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CacheRef")
            .field("sender", &"SaltCacheSender")
            .field("key", &String::from_utf8_lossy(self.key))
            .finish()
    }
}

/// Resolve the real git directory of the worktree at `repo_path`.
///
/// `repo_path/.git` is a directory for a normal clone, but a
/// `gitdir: <path>` pointer file for linked worktrees (`git worktree add`)
/// and submodules. Naively joining the cache onto the pointer *file* yields a
/// path whose parent does not exist, so every lock/write fails with "os
/// error 3" and the cache silently stops working (breaking clean
/// determinism exactly there).
///
/// Resolution strategy: parse the pointer file ourselves instead of spawning
/// `git rev-parse --git-path`. The filter drivers open the repo and touch the
/// cache once per file, and a git subprocess costs 20-50ms on Windows, while
/// reading a ~60-byte file is free. Pointer parsing is exactly what git's own
/// `read_gitfile` does and covers every real-world case where `.git` is not
/// the gitdir; `--git-path`'s extra authority only matters for config
/// overrides of *well-known* names (e.g. `core.hooksPath`), which cannot
/// apply to our private cache name. A relative `gitdir:` target is resolved
/// against the worktree root (a moved/cloned repo may contain one).
fn resolve_git_dir(repo_path: &Path) -> PathBuf {
    let dot_git = repo_path.join(".git");
    if dot_git.is_dir() {
        return dot_git;
    }
    if let Ok(content) = std::fs::read_to_string(&dot_git)
        && let Some(target) = content.trim().strip_prefix("gitdir:")
    {
        let target = Path::new(target.trim());
        // The target is the per-worktree gitdir, e.g.
        // `<main>/.git/worktrees/<name>` or `<parent>/.git/modules/<name>`.
        return if target.is_absolute() {
            target.to_path_buf()
        } else {
            repo_path.join(target)
        };
    }
    // Not a directory and not a parseable pointer: keep the legacy location
    // so behavior degrades exactly as before (writes fail loudly in logs).
    dot_git
}

/// Returns the cache file path for the given repo.
fn cache_path(repo_path: &Path) -> PathBuf {
    resolve_git_dir(repo_path).join(CACHE_FILENAME)
}

// ---------------------------------------------------------------------------
// Key normalization (case-insensitive filesystems)
// ---------------------------------------------------------------------------

/// Whether cache keys are case-normalized on this platform.
const CASE_INSENSITIVE_FS: bool = cfg!(windows) || cfg!(target_os = "macos");

/// Canonical storage form of a cache key: raw bytes on case-sensitive
/// platforms, ASCII-lowercased on case-insensitive ones.
///
/// On Windows/macOS the same file can be spelled differently by git's index
/// (the filter's `%f`) and by on-disk enumeration (manual commands); storing
/// one canonical form lets both workflows share entries. ASCII-only folding:
/// bytes >= 0x80 pass through untouched, so multi-byte UTF-8 path sequences
/// are never corrupted.
fn storage_key(key: &[u8]) -> Cow<'_, [u8]> {
    if !CASE_INSENSITIVE_FS || !key.iter().any(u8::is_ascii_uppercase) {
        Cow::Borrowed(key)
    } else {
        Cow::Owned(key.to_ascii_lowercase())
    }
}

/// Look `key` up in `map`, honoring the raw-case entries written by <= 3.1.
///
/// Reads try the raw spelling first, then the normalized form, so legacy
/// entries stay reachable without a cache migration. A legacy entry whose
/// spelling differs from both lookups (e.g. a case-only rename happened since
/// it was written) is unreachable — it costs one fresh entry once, after which
/// the cache converges to normalized keys.
fn lookup_entry<'a>(map: &'a HashMap<Vec<u8>, CachedEntry>, key: &[u8]) -> Option<&'a CachedEntry> {
    if !CASE_INSENSITIVE_FS {
        return map.get(key);
    }
    let folded = storage_key(key);
    map.get(key).or_else(|| map.get(folded.as_ref()))
}

/// Canonicalize every key of a map destined for the disk (see
/// [`storage_key`]).
///
/// Collision policy when both spellings exist: the last one written wins —
/// both spellings denote the same file, so neither choice loses information.
fn normalize_keys(map: HashMap<Vec<u8>, CachedEntry>) -> HashMap<Vec<u8>, CachedEntry> {
    if !CASE_INSENSITIVE_FS {
        return map;
    }
    map.into_iter()
        .map(|(k, v)| (storage_key(&k).into_owned(), v))
        .collect()
}

// ---------------------------------------------------------------------------
// Read Path — one-shot read + rkyv
// ---------------------------------------------------------------------------

/// In-memory salt cache snapshot used during **encryption** to look up
/// previously cached `salt/file_id` values.
///
/// Deliberately not mmap-backed: an active mapping blocks the atomic
/// rename-replace of the cache on Windows (see module docs). The whole file
/// is read and deserialized once; lookups are plain `HashMap` gets.
pub struct SaltCacheReader {
    map: HashMap<Vec<u8>, CachedEntry>,
}

impl SaltCacheReader {
    /// Open the salt cache for the given repository.
    ///
    /// If the cache file does not exist or is corrupted, returns an empty
    /// reader (all lookups will return `None`). This never fails — a missing
    /// or corrupt cache simply means we start fresh (new salts will be
    /// generated during encryption).
    #[must_use]
    pub fn load(repo_path: &Path) -> Self {
        let path = cache_path(repo_path);

        if !path.exists() {
            debug!("Salt cache not found at {}", path.display());
            return Self {
                map: HashMap::new(),
            };
        }
        Self {
            map: read_cache_file(&path).unwrap_or_default(),
        }
    }

    /// Look up a cached entry by repo-relative path key (bytes).
    ///
    /// The `key` should be forward-slash normalized repo-relative path bytes,
    /// computed by the caller.
    ///
    /// Returns `None` if no cache file exists or the key is not cached.
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<CachedEntry> {
        lookup_entry(&self.map, key).cloned()
    }
}

/// Read and deserialize the cache at `path`; `None` (with a warn) when it
/// cannot be read or parsed.
fn read_cache_file(path: &Path) -> Option<HashMap<Vec<u8>, CachedEntry>> {
    match std::fs::read(path) {
        Ok(bytes) => match rkyv::from_bytes::<HashMap<Vec<u8>, CachedEntry>, RkyvError>(&bytes) {
            Ok(map) => Some(map),
            Err(e) => {
                warn!("Corrupted salt cache at {}: {e}", path.display());
                None
            },
        },
        Err(e) => {
            warn!("Failed to read salt cache at {}: {e}", path.display());
            None
        },
    }
}

// ---------------------------------------------------------------------------
// Write Path — mpsc collection + rkyv serialization
// ---------------------------------------------------------------------------

/// Which path is writing the cache — decides how loudly failures are logged.
enum Writer {
    /// Git filter driver: its process logger defaults to error-only (stdout
    /// carries the data stream), so a `warn` is invisible — and a silently
    /// lost entry breaks clean determinism, the exact failure this cache
    /// exists to prevent.
    Filter,
    /// Interactive batch command (`git-se d`): default logging shows `warn`.
    Batch,
}

impl Writer {
    /// Report a merge/write failure at the visibility the calling path gets.
    fn report_write_failure(self, msg: fmt::Arguments<'_>) {
        match self {
            Self::Filter => error!("{msg}"),
            Self::Batch => warn!("{msg}"),
        }
    }
}

/// Acquire the exclusive `<cache>.lock`, then run `body` with it held.
///
/// This is the single-writer protocol shared by every cache mutation (filter
/// merges and batch saves alike); without it, one writer's read-modify-write
/// would silently drop entries another writer merged in between. The lock is
/// advisory and released automatically when the process exits, so a crashed
/// writer cannot leave a stale lock behind. Reads elsewhere need no lock:
/// [`atomic_write`] renames into place, so a concurrent reader always sees
/// the old or the new complete file.
///
/// Lock-acquisition failures are logged at `error` regardless of the caller
/// (they indicate a broken environment such as a read-only `.git`), unlike
/// merge write failures, which follow the caller's [`Writer`] visibility.
fn with_cache_lock<T>(repo_path: &Path, body: impl FnOnce(&Path) -> T) -> Option<T> {
    let git_dir = resolve_git_dir(repo_path);
    let lock_path = git_dir.join(format!("{CACHE_FILENAME}.lock"));
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .and_then(|file| {
            file.lock()?;
            Ok(file)
        });
    match lock {
        Ok(_guard) => Some(body(&git_dir.join(CACHE_FILENAME))),
        Err(e) => {
            error!("Failed to lock salt cache {}: {e}", lock_path.display());
            None
        },
    }
}

/// Merge `new` (normalized) into `map` (new entries win), returning whether
/// anything actually changed.
fn merge_into(map: &mut HashMap<Vec<u8>, CachedEntry>, new: HashMap<Vec<u8>, CachedEntry>) -> bool {
    let mut changed = false;
    for (k, v) in new {
        changed |= map.get(&k).is_none_or(|old| *old != v);
        map.insert(k, v);
    }
    changed
}

/// Serialize `map` and write it atomically to `path`, reporting failures at
/// the given [`Writer`] visibility.
fn persist_map(path: &Path, map: &HashMap<Vec<u8>, CachedEntry>, writer: Writer) {
    match rkyv::to_bytes::<RkyvError>(map) {
        Ok(bytes) => {
            if let Err(e) = atomic_write(path, bytes.as_slice()) {
                writer.report_write_failure(format_args!(
                    "Failed to save salt cache to {}: {e}",
                    path.display()
                ));
            } else {
                debug!(
                    "Saved salt cache with {} entries to {}",
                    map.len(),
                    path.display()
                );
            }
        },
        Err(e) => writer.report_write_failure(format_args!("Failed to serialize salt cache: {e}")),
    }
}

/// Merge `entries` over the on-disk cache at `path` (new entries win) and
/// write it atomically.
///
/// Best-effort: failures are logged per `writer`, never propagated (a lost
/// entry only costs ciphertext determinism, never data). The write is skipped
/// when every entry is already on disk verbatim — the common case for
/// repeated smudges of cached paths and re-decrypts of an unchanged repo,
/// which previously rewrote the whole file each time (O(N²) bytes for N files
/// in a mass operation).
fn write_merged(path: &Path, entries: HashMap<Vec<u8>, CachedEntry>, writer: Writer) {
    let new = normalize_keys(entries);
    let mut map = read_cache_file(path).unwrap_or_default();
    if !merge_into(&mut map, new) {
        debug!(
            "Salt cache unchanged at {} ({} entries), skipping rewrite",
            path.display(),
            map.len()
        );
        return;
    }
    persist_map(path, &map, writer);
}

/// Thread-safe sender for cache entries, safe to share across worker threads.
///
/// Workers call [`insert`](Self::insert) to send `(key, entry)` pairs
/// through an internal `mpsc` channel. After all parallel work completes,
/// the paired [`SaltCacheSaver`] collects and persists the entries.
pub struct SaltCacheSender {
    tx: mpsc::Sender<(Vec<u8>, CachedEntry)>,
}

impl SaltCacheSender {
    /// Send a cache entry for the given repo-relative path key (bytes).
    ///
    /// The `key` should be forward-slash normalized repo-relative path bytes,
    /// computed by the caller.
    ///
    /// This is thread-safe (`&Self`) and non-blocking. Errors (e.g. channel
    /// closed) are silently ignored because cache persistence is non-critical.
    pub fn insert(&self, key: &[u8], entry: CachedEntry) {
        let _ = self.tx.send((key.to_vec(), entry));
    }
}

/// Receiver that collects and persists cache entries to disk.
///
/// Created paired with a [`SaltCacheSender`] via [`create_writer`]. After all
/// parallel work completes, call [`save`](Self::save) to collect entries,
/// merge with any existing on-disk cache, and serialize via rkyv. Long
/// batches can flush intermediate progress with
/// [`checkpoint`](Self::checkpoint).
///
/// This type is **not** `Sync` — it should only be used on the main thread
/// after parallel work completes.
///
/// # Drop safety
///
/// [`Drop`] is implemented as a safety net: if [`save`](Self::save) is not
/// called (e.g. due to a panic during parallel decryption), any entries
/// already buffered in the channel are still persisted. This honors the
/// module-level contract that partial progress is preserved on error. Note
/// that release builds use `panic = "abort"`, under which `Drop` never runs —
/// callers driving long batches should use [`checkpoint`](Self::checkpoint)
/// instead of relying on this fallback.
pub struct SaltCacheSaver {
    /// `Option` so [`save_inner`] can take it exactly once; subsequent `Drop`
    /// becomes a no-op.
    rx: Option<mpsc::Receiver<(Vec<u8>, CachedEntry)>>,
    repo_path: PathBuf,
}

impl SaltCacheSaver {
    /// Persist all collected entries to disk (best-effort, atomic).
    ///
    /// 1. Collects all `(key, entry)` pairs currently buffered in the channel via
    ///    [`mpsc::Receiver::try_iter`] (non-blocking — by the time this is called, all workers have
    ///    finished, so every sent entry is already buffered).
    /// 2. Merges with any existing on-disk cache (existing entries are kept only if no new entry
    ///    overrides them) under the exclusive cache lock.
    /// 3. Serializes via rkyv and writes atomically to the cache file in the repo's real git
    ///    directory (worktree pointers included).
    ///
    /// Safe to call exactly once; a paired [`Drop`] impl guards the
    /// panic-on-drop path. Errors are logged but not propagated because cache
    /// persistence is non-critical: losing the cache only means the next
    /// encryption uses fresh salts.
    pub fn save(mut self) {
        self.save_inner();
    }

    fn save_inner(&mut self) {
        // `take()` ensures the body runs at most once across `save()` + `Drop`.
        let Some(rx) = self.rx.take() else {
            return;
        };

        // Use `try_iter` (non-blocking) rather than `into_iter` so that:
        //   - explicit `save()` does not require the caller to drop the sender first (removing a
        //     brittle ordering contract);
        //   - the `Drop` impl cannot deadlock if the paired `SaltCacheSender` is dropped after
        //     `self` under non-2024 drop ordering.
        // All workers have returned by the time we get here, so every
        // sent entry is already in the channel buffer.
        let entries: HashMap<Vec<u8>, CachedEntry> = rx.try_iter().collect();
        persist_entries(&self.repo_path, entries);
    }

    /// Persist the entries buffered so far and keep collecting more.
    ///
    /// A periodic save point bounds cache loss when the process dies without
    /// unwinding (release builds abort on panic, so the [`Drop`] fallback
    /// never runs mid-batch): only the entries of the current chunk are at
    /// risk, not those of the whole run.
    pub fn checkpoint(&mut self) {
        let Some(rx) = &self.rx else {
            return;
        };
        let entries: HashMap<Vec<u8>, CachedEntry> = rx.try_iter().collect();
        persist_entries(&self.repo_path, entries);
    }
}

/// Flush collected entries through the locked merge path (no-op when empty).
fn persist_entries(repo_path: &Path, entries: HashMap<Vec<u8>, CachedEntry>) {
    if entries.is_empty() {
        debug!("No cache entries to save");
        return;
    }
    with_cache_lock(repo_path, |path| write_merged(path, entries, Writer::Batch));
}

/// Create a paired sender/saver for collecting cache entries.
///
/// The sender is `Sync` and can be shared across worker threads. The saver
/// should be kept on the main thread and `.save()`d after parallel work
/// completes. If `.save()` is not called, [`SaltCacheSaver::drop`] will
/// persist any buffered entries as a safety net.
#[must_use]
pub fn create_writer(repo_path: &Path) -> (SaltCacheSender, SaltCacheSaver) {
    let (tx, rx) = mpsc::channel();
    (SaltCacheSender { tx }, SaltCacheSaver {
        rx: Some(rx),
        repo_path: repo_path.to_path_buf(),
    })
}

/// Merge entries into the on-disk cache from a single-file process (the git
/// clean/smudge drivers).
///
/// Git runs filter processes concurrently (e.g. parallel smudge during
/// checkout), so the read-modify-write cycle is serialized with the exclusive
/// OS lock on `<cache>.lock` (see [`with_cache_lock`]).
///
/// Failures log at `error`: filter drivers default to error-only logging, and
/// a lost entry silently breaks clean determinism.
pub fn merge_entries<I>(repo_path: &Path, entries: I)
where
    I: IntoIterator<Item = (Vec<u8>, CachedEntry)>,
{
    let map: HashMap<Vec<u8>, CachedEntry> = entries.into_iter().collect();
    if map.is_empty() {
        return;
    }
    with_cache_lock(repo_path, |path| write_merged(path, map, Writer::Filter));
}

/// Resolve the cache entry for `key` before a first-time encryption,
/// converging concurrent writers on a single entry.
///
/// Two filter processes can miss on the same path simultaneously (parallel
/// `git add` of new files) and each mint a random entry; with a plain
/// last-writer-wins merge the loser's ciphertext would no longer match the
/// cache, resurfacing as a phantom modification on the next clean. Here the
/// decision and the cache write happen atomically under the exclusive lock:
/// if another writer got there first, its entry is adopted *before* any
/// encryption happens; otherwise the candidate is persisted and used. The
/// returned entry therefore always matches the on-disk cache from the moment
/// the lock is released — no re-encryption or post-hoc fixup is needed.
///
/// Returns the `candidate` unchanged when the cache is unwritable (missing
/// `.git`, read-only filesystem, ...): encryption proceeds and only this
/// path's determinism is at risk — the same best-effort contract as
/// [`merge_entries`].
#[must_use]
pub fn resolve_or_insert(repo_path: &Path, key: &[u8], candidate: CachedEntry) -> CachedEntry {
    let stored = storage_key(key).into_owned();
    let fallback = candidate.clone();
    with_cache_lock(repo_path, |path| {
        let mut map = read_cache_file(path).unwrap_or_default();
        if let Some(entry) = lookup_entry(&map, key) {
            debug!(
                "Salt cache entry appeared concurrently for {}, adopting it",
                String::from_utf8_lossy(key)
            );
            return entry.clone();
        }
        map.insert(stored, candidate.clone());
        persist_map(path, &map, Writer::Filter);
        candidate
    })
    .unwrap_or(fallback)
}

impl Drop for SaltCacheSaver {
    fn drop(&mut self) {
        self.save_inner();
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn make_entry(salt_byte: u8, file_id_byte: u8) -> CachedEntry {
        CachedEntry {
            salt: [salt_byte; SALT_LEN],
            file_id: [file_id_byte; FILE_ID_LEN],
        }
    }

    #[test]
    fn test_reader_get_from_wrong_path() {
        let dir = TempDir::new().unwrap();
        let reader = SaltCacheReader::load(dir.path());
        assert_eq!(reader.get(b"test.txt"), None);
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
            sender.insert(b"file1.txt", entry1.clone());
            sender.insert(b"sub/file2.txt", entry2.clone());
            // Drop sender to close the channel before saving.
            drop(sender);
            saver.save();
        }

        // Load via reader and verify.
        let reader = SaltCacheReader::load(repo);
        assert_eq!(reader.get(b"file1.txt"), Some(entry1));
        assert_eq!(reader.get(b"sub/file2.txt"), Some(entry2));
        assert_eq!(reader.get(b"nonexistent.txt"), None);
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
        assert_eq!(reader.get(b"test.txt"), None);
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
            sender.insert(b"test.txt", entry1);
            sender.insert(b"test.txt", entry2.clone());
            drop(sender);
            saver.save();
        }

        let reader = SaltCacheReader::load(repo);
        assert_eq!(reader.get(b"test.txt"), Some(entry2));
    }

    #[test]
    fn test_relative_path_key_persistence() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let entry = make_entry(0x55, 0x66);

        {
            let (sender, saver) = create_writer(repo);
            sender.insert(b"subdir/file.txt", entry.clone());
            drop(sender);
            saver.save();
        }

        let reader = SaltCacheReader::load(repo);
        assert_eq!(reader.get(b"subdir/file.txt"), Some(entry));
    }

    #[test]
    fn test_merge_with_existing() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let entry_a = make_entry(0xaa, 0xbb);
        let entry_b = make_entry(0xcc, 0xdd);

        // Save initial entry.
        {
            let (sender, saver) = create_writer(repo);
            sender.insert(b"existing.txt", entry_a.clone());
            drop(sender);
            saver.save();
        }

        // Save a new entry — the existing one should be preserved via merge.
        {
            let (sender, saver) = create_writer(repo);
            sender.insert(b"new.txt", entry_b.clone());
            drop(sender);
            saver.save();
        }

        let reader = SaltCacheReader::load(repo);
        assert_eq!(reader.get(b"existing.txt"), Some(entry_a));
        assert_eq!(reader.get(b"new.txt"), Some(entry_b));
    }

    #[test]
    fn test_merge_entries_single_writer_api() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let entry = make_entry(0x77, 0x88);
        merge_entries(repo, [(b"f.txt".to_vec(), entry)]);

        // merges with, not replaces, the existing cache
        let (sender, saver) = create_writer(repo);
        sender.insert(b"other.txt", make_entry(0x99, 0xaa));
        drop(sender);
        saver.save();

        merge_entries(repo, [(b"f.txt".to_vec(), make_entry(0xbb, 0xcc))]);

        let reader = SaltCacheReader::load(repo);
        assert_eq!(reader.get(b"f.txt"), Some(make_entry(0xbb, 0xcc)));
        assert_eq!(reader.get(b"other.txt"), Some(make_entry(0x99, 0xaa)));
    }

    #[test]
    fn test_saver_does_not_lose_concurrent_filter_entries() {
        // Regression for the lost-update window: the batch saver used to
        // rewrite the whole cache without the lock, dropping entries a
        // concurrent filter process had merged in between.
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let (sender, saver) = create_writer(repo);
        sender.insert(b"batch.txt", make_entry(0x11, 0x22));
        // concurrent filter write while the batch is still running
        merge_entries(repo, [(b"filter.txt".to_vec(), make_entry(0x33, 0x44))]);
        drop(sender);
        saver.save();

        let reader = SaltCacheReader::load(repo);
        assert_eq!(reader.get(b"batch.txt"), Some(make_entry(0x11, 0x22)));
        assert_eq!(reader.get(b"filter.txt"), Some(make_entry(0x33, 0x44)));
    }

    #[test]
    fn test_resolve_or_insert_adopts_existing_entry() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let existing = make_entry(0x11, 0x22);
        merge_entries(repo, [(b"f.txt".to_vec(), existing.clone())]);

        // A concurrent writer "won the race": its entry is adopted, the
        // candidate discarded.
        let candidate = make_entry(0x33, 0x44);
        assert_eq!(resolve_or_insert(repo, b"f.txt", candidate), existing);

        // First writer for a new key: candidate is used and persisted.
        let fresh = make_entry(0x55, 0x66);
        assert_eq!(resolve_or_insert(repo, b"new.txt", fresh.clone()), fresh);
        let reader = SaltCacheReader::load(repo);
        assert_eq!(reader.get(b"new.txt"), Some(fresh));
    }

    #[test]
    fn test_checkpoint_persists_early_entries() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let (sender, mut saver) = create_writer(repo);
        sender.insert(b"a.txt", make_entry(0x11, 0x22));
        saver.checkpoint();
        sender.insert(b"b.txt", make_entry(0x33, 0x44));
        drop(sender);
        saver.save();

        let reader = SaltCacheReader::load(repo);
        assert_eq!(reader.get(b"a.txt"), Some(make_entry(0x11, 0x22)));
        assert_eq!(reader.get(b"b.txt"), Some(make_entry(0x33, 0x44)));
    }

    #[test]
    fn test_cache_lands_in_worktree_gitdir_behind_pointer() {
        // A linked worktree: `.git` is a `gitdir:` pointer file; joining the
        // cache onto the pointer itself would produce a path under a
        // nonexistent directory (os error 3 on every lock/write).
        let dir = TempDir::new().unwrap();
        let main_git = dir.path().join("main").join(".git");
        let wt_git = main_git.join("worktrees").join("wt");
        std::fs::create_dir_all(&wt_git).unwrap();
        let wt = dir.path().join("wt");
        std::fs::create_dir_all(&wt).unwrap();
        std::fs::write(wt.join(".git"), format!("gitdir: {}\n", wt_git.display())).unwrap();

        assert_eq!(cache_path(&wt), wt_git.join(CACHE_FILENAME));

        // The full lock-guarded write path resolves the same way.
        let entry = make_entry(0x11, 0x22);
        merge_entries(&wt, [(b"f.txt".to_vec(), entry.clone())]);
        assert!(wt_git.join(CACHE_FILENAME).exists());
        assert!(wt_git.join(format!("{CACHE_FILENAME}.lock")).exists());
        assert_eq!(SaltCacheReader::load(&wt).get(b"f.txt"), Some(entry));
    }

    #[test]
    fn test_cache_resolves_relative_gitdir_pointer() {
        // Repos can be moved so that the pointer target becomes relative;
        // it must resolve against the worktree root. (Joining keeps the `..`
        // component; comparison goes through Absolutize, which normalizes.)
        use path_absolutize::Absolutize;

        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("main").join(".git")).unwrap();
        let wt = dir.path().join("wt");
        std::fs::create_dir_all(&wt).unwrap();
        std::fs::write(wt.join(".git"), b"gitdir: ../main/.git\n").unwrap();

        assert_eq!(
            cache_path(&wt).absolutize().unwrap(),
            dir.path()
                .join("main")
                .join(".git")
                .join(CACHE_FILENAME)
                .absolutize()
                .unwrap()
        );
    }

    #[test]
    fn test_case_normalized_keys() {
        let dir = TempDir::new().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let entry = make_entry(0x11, 0x22);
        {
            let (sender, saver) = create_writer(repo);
            sender.insert(b"Foo.txt", entry.clone());
            drop(sender);
            saver.save();
        }

        let reader = SaltCacheReader::load(repo);
        // exact spelling always hits
        assert_eq!(reader.get(b"Foo.txt"), Some(entry.clone()));
        if CASE_INSENSITIVE_FS {
            // any other spelling of the same file converges on the entry
            assert_eq!(reader.get(b"foo.txt"), Some(entry.clone()));
            assert_eq!(reader.get(b"FOO.TXT"), Some(entry.clone()));
        } else {
            // case-sensitive platforms keep spellings distinct
            assert_eq!(reader.get(b"foo.txt"), None);
        }

        // resolve_or_insert also converges spellings on the same entry
        let candidate = make_entry(0x33, 0x44);
        let resolved = resolve_or_insert(repo, b"foo.TXT", candidate);
        assert_eq!(resolved, entry);
    }
}
