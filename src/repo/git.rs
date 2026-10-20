//! Git subprocess plumbing shared by the repo commands.
//!
//! Holds a persistent `git cat-file --batch` session ([`CatFileBatch`]) for
//! streaming blob reads, the NUL-separated output parsers, the crypt-list
//! coverage matcher, and the `Repo` methods that shell out to git (running
//! commands, enumerating the HEAD tree and the index).

use std::{
    collections::{BTreeMap, HashMap},
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
};

use super::Repo;
use crate::error::{Error, Result};

/// A persistent `git cat-file --batch` session.
///
/// Spawning one git process per blob costs 20-50ms on Windows; at a thousand
/// staged files the pre-commit check spent 30-50s just spawning git. One
/// session serves any number of lookups over a single pipe pair. Requests
/// are answered strictly in lockstep (write one request line, then read the
/// full response) so arbitrarily large blobs cannot deadlock on a full
/// pipe.
pub(super) struct CatFileBatch {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
}

impl CatFileBatch {
    pub(super) fn spawn(cwd: &Path) -> Result<Self> {
        let mut child = Command::new("git")
            .current_dir(cwd)
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Per-object errors are conveyed by the batch protocol itself
            // ("<spec> missing"); git's stderr would only add noise.
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::Other("git cat-file stdin unavailable".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::Other("git cat-file stdout unavailable".to_string()))?;
        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    /// Send one lookup and parse its response header: `Some(size)` means a
    /// `<oid> <type> <size> LF` header whose payload of `size` bytes (plus a
    /// trailing LF) is now waiting on the pipe; `None` means "missing".
    fn response_header(&mut self, oid: &str) -> Result<Option<usize>> {
        self.stdin.write_all(oid.as_bytes())?;
        self.stdin.write_all(b"\n")?;
        self.stdin.flush()?;
        let mut header = String::new();
        self.stdout.read_line(&mut header)?;
        let header = header.trim_end();
        // Response header: `<oid> <type> <size>` or `<spec> missing`.
        match header
            .rsplit_once(' ')
            .and_then(|(_, size)| size.parse::<usize>().ok())
        {
            Some(size) => Ok(Some(size)),
            None if header.ends_with(" missing") => Ok(None),
            None => Err(Error::Other(format!(
                "unexpected git cat-file response: {header}"
            ))),
        }
    }

    /// Read only the leading bytes of one blob (up to `keep`, clamped to the
    /// payload size) and drain the remainder without buffering it; `None`
    /// when the object is missing.
    pub(super) fn blob_prefix(&mut self, oid: &str, keep: usize) -> Result<Option<Vec<u8>>> {
        let Some(mut stream) = self.blob_stream(oid)? else {
            return Ok(None);
        };
        stream.take_prefix(keep).map(Some)
    }

    /// Begin reading one blob payload; `None` when the object is missing.
    /// The returned stream must be fully consumed, or ended via
    /// [`BlobStream::skip_to_end`], before the next lookup on this session:
    /// leftover bytes would desync every later response.
    pub(super) fn blob_stream(&mut self, oid: &str) -> Result<Option<BlobStream<'_>>> {
        let Some(size) = self.response_header(oid)? else {
            return Ok(None);
        };
        Ok(Some(BlobStream {
            batch: self,
            size,
            remaining: size,
        }))
    }
}

/// A blob payload currently being read from a [`CatFileBatch`] session.
///
/// Holds the borrow while the caller consumes the payload piecewise; the
/// session stays aligned as long as every stream is read to its end or
/// explicitly skipped.
pub(super) struct BlobStream<'a> {
    batch: &'a mut CatFileBatch,
    /// Payload size advertised by the response header.
    size: usize,
    /// Payload bytes not yet consumed.
    remaining: usize,
}

impl BlobStream<'_> {
    /// The payload size advertised by the response header.
    #[must_use]
    pub(super) const fn len(&self) -> usize {
        self.size
    }

    /// Read exactly `buf.len()` payload bytes; the caller must stay within
    /// [`BlobStream::len`].
    pub(super) fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        debug_assert!(
            buf.len() <= self.remaining,
            "blob read past the advertised payload size"
        );
        self.batch.stdout.read_exact(buf)?;
        self.remaining -= buf.len();
        Ok(())
    }

    /// Read up to `buf.len()` payload bytes (fewer only at the payload end).
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let want = buf.len().min(self.remaining);
        let n = self.batch.stdout.read(&mut buf[..want])?;
        self.remaining -= n;
        Ok(n)
    }

    /// Read the first `keep` payload bytes (clamped to the payload size),
    /// end the stream and return them: magic checks only need the leading
    /// bytes, and draining keeps the session aligned without holding the
    /// whole blob in memory.
    fn take_prefix(&mut self, keep: usize) -> Result<Vec<u8>> {
        let mut head = vec![0u8; keep.min(self.size)];
        self.read_exact(&mut head)?;
        self.skip_to_end()?;
        Ok(head)
    }

    /// Consume and discard the unread payload plus the trailing LF
    /// terminator, leaving the session ready for the next request. The
    /// payload bytes still cross the pipe (the protocol leaves no way
    /// around them) but never the heap.
    pub(super) fn skip_to_end(&mut self) -> Result<()> {
        if self.remaining > 0 {
            let remaining = self.remaining as u64;
            let mut payload = self.batch.stdout.by_ref().take(remaining);
            let copied = std::io::copy(&mut payload, &mut std::io::sink())?;
            if copied < remaining {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "git cat-file payload ended early",
                )
                .into());
            }
            self.remaining = 0;
        }
        let mut lf = [0u8; 1];
        self.batch.stdout.read_exact(&mut lf)?;
        Ok(())
    }
}

/// Chunk size for the streaming blob-vs-file compare.
const COMPARE_CHUNK: usize = 8 * 1024;

/// Read up to `buf.len()` bytes from `file`, filling as much as possible
/// before EOF; returns the number of bytes read.
pub(super) fn read_prefix(file: &mut std::fs::File, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

/// Verdict of [`stream_eq_file`].
pub(super) enum CompareOutcome {
    /// Both sides read to the blob's end and matched byte-for-byte.
    Equal,
    /// The contents differ (a file ending early mid-compare included).
    Different,
    /// The file side failed to read mid-compare; the blob session is still
    /// healthy, so only the file must be treated as unreadable.
    FileUnreadable,
}

/// Compare the unconsumed blob payload against the remainder of `file` in
/// fixed chunks, stopping at the first difference.
///
/// The caller has already matched the total lengths; a file that ends early
/// — truncated concurrently with the compare — simply reads as differing.
/// A file read error is reported as [`CompareOutcome::FileUnreadable`] so
/// callers can fold it into their unreadable-file handling; errors from the
/// blob side stay `Err` — they mean the batch session is broken, not that
/// the file is unreadable.
pub(super) fn stream_eq_file(
    stream: &mut BlobStream<'_>,
    file: &mut std::fs::File,
) -> Result<CompareOutcome> {
    let mut blob_chunk = [0u8; COMPARE_CHUNK];
    let mut file_chunk = [0u8; COMPARE_CHUNK];
    loop {
        let n = stream.read(&mut blob_chunk)?;
        if n == 0 {
            return Ok(CompareOutcome::Equal);
        }
        let Ok(filled) = read_prefix(file, &mut file_chunk[..n]) else {
            return Ok(CompareOutcome::FileUnreadable);
        };
        if filled < n || blob_chunk[..n] != file_chunk[..n] {
            return Ok(CompareOutcome::Different);
        }
    }
}
impl Drop for CatFileBatch {
    fn drop(&mut self) {
        // The session lives exactly as long as the caller's questions;
        // kill+reap deterministically cleans up even mid-stream.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Split raw NUL-terminated git output into records (dropping the empty
/// trailing record). Every multi-path git parse goes through here so the
/// `-z` handling lives in exactly one place.
pub(super) fn nul_records(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes.split(|&b| b == 0).filter(|r| !r.is_empty())
}

/// Split a byte record at its first `sep` byte (`slice::split_once` is not
/// stable for byte slices yet).
fn split_byte_record(record: &[u8], sep: u8) -> Option<(&[u8], &[u8])> {
    record
        .iter()
        .position(|&b| b == sep)
        .map(|i| (&record[..i], &record[i + 1..]))
}

/// Crypt-list coverage matcher over repo-relative (forward-slashed) paths.
///
/// The per-entry directory prefixes are built once per query batch, so
/// per-file checks neither rescan-and-reallocate the list nor repeat the
/// prefix concatenation.
///
/// Deliberately free of the walker's ignore semantics: this predicate feeds
/// staged/index queries, and a tracked, staged file must never be hidden by
/// .gitignore rules (the pre-commit check would silently skip it). Crypt
/// entries are plain paths, never globs, so the prefix test is exact.
pub(super) struct CryptCoverage {
    /// (entry, entry + "/") per crypt-list line.
    prefixes: Vec<(String, String)>,
}

impl CryptCoverage {
    pub(super) fn new(crypt_list: &[String]) -> Self {
        Self {
            prefixes: crypt_list
                .iter()
                .map(|entry| (entry.clone(), format!("{entry}/")))
                .collect(),
        }
    }

    /// Whether `rel` is an exact crypt-list entry or lies underneath one.
    pub(super) fn covers(&self, rel: &str) -> bool {
        self.prefixes
            .iter()
            .any(|(file, dir)| rel == file || rel.starts_with(dir.as_str()))
    }
}

impl Repo {
    /// Run a `git` command in the repo, discarding its stdout/stderr.
    pub fn run(&self, args: &[&str]) -> Result<()> {
        let output = Command::new("git")
            .current_dir(&self.path)
            .args(args)
            .output()?;
        if !output.status.success() {
            return Err(Error::Git(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ));
        }
        Ok(())
    }

    /// Run a `git` command and return its stdout as a `String`.
    pub fn run_with_output(&self, args: &[&str]) -> Result<String> {
        String::from_utf8(self.run_with_output_bytes(args)?)
            .map_err(|e| Error::Other(format!("git output not UTF-8: {e}")))
    }

    /// Run a `git` command and return its raw stdout bytes — the base for
    /// every `-z` (NUL-separated) parse, where text conversion would be
    /// lossy for arbitrary path bytes.
    pub(super) fn run_with_output_bytes(&self, args: &[&str]) -> Result<Vec<u8>> {
        let mut cmd = Command::new("git");

        // Force English output in tests so we can match on stderr reliably.
        if cfg!(test) {
            cmd.env("LC_ALL", "C.UTF-8").env("LANGUAGE", "C.UTF-8");
        }

        let output = cmd.current_dir(&self.path).args(args).output()?;
        if !output.status.success() {
            return Err(Error::Git(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ));
        }
        Ok(output.stdout)
    }

    /// Crypt-list files staged for the current commit, with the oid of their
    /// staged (index) blob: `Vec<(repo-relative path, oid)>`.
    ///
    /// Two git processes total, regardless of file count:
    /// - `git diff --cached --name-only -z --no-renames --diff-filter=ACMR` enumerates the staged
    ///   paths raw (NUL-separated; `-z` disables C-quoting so any byte spelling survives).
    ///   `--no-renames` keeps records single-path (a rename would drag the old path along).
    /// - `git ls-files -s -z` maps every index path to its full blob oid (`diff --raw` abbreviates
    ///   oids, which could turn ambiguous in huge repositories; ls-files never does).
    pub(super) fn staged_crypt_blobs(&self) -> Result<Vec<(String, String)>> {
        let names = self.run_with_output_bytes(&[
            "diff",
            "--cached",
            "--name-only",
            "-z",
            "--no-renames",
            "--diff-filter=ACMR",
        ])?;
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let coverage = CryptCoverage::new(&self.conf.crypt_list);
        let index = self.index_blobs()?;
        Ok(nul_records(&names)
            .filter(|p| coverage.covers(&String::from_utf8_lossy(p)))
            .filter_map(|p| {
                index
                    .get(p)
                    .map(|oid| (String::from_utf8_lossy(p).into_owned(), oid.clone()))
            })
            .collect())
    }

    /// Full blob oid for every staged path, keyed by raw path bytes.
    /// (`git ls-files -s -z`: `<mode> <oid> <stage>\t<path>` per NUL.)
    pub(super) fn index_blobs(&self) -> Result<HashMap<Vec<u8>, String>> {
        let out = self.run_with_output_bytes(&["ls-files", "-s", "-z"])?;
        let mut map = HashMap::new();
        for record in nul_records(&out) {
            let Some((meta, path)) = split_byte_record(record, b'\t') else {
                continue;
            };
            let Some(oid) = meta.split(|&b| b == b' ').nth(1) else {
                continue;
            };
            map.insert(path.to_vec(), String::from_utf8_lossy(oid).into_owned());
        }
        Ok(map)
    }

    /// Raw path bytes → full blob oid for every blob in the HEAD tree
    /// (`git ls-tree -r -z HEAD`: `<mode> <type> <oid>\t<path>` per NUL).
    /// Empty when HEAD does not exist yet (fresh repository).
    pub(super) fn head_tree_blobs(&self) -> Result<BTreeMap<Vec<u8>, String>> {
        if !self.head_exists()? {
            return Ok(BTreeMap::new());
        }
        let out = self.run_with_output_bytes(&["ls-tree", "-r", "-z", "HEAD"])?;
        let mut map = BTreeMap::new();
        for record in nul_records(&out) {
            let Some((meta, path)) = split_byte_record(record, b'\t') else {
                continue;
            };
            let mut fields = meta.split(|&b| b == b' ');
            let kind = fields.nth(1);
            let oid = fields.next();
            // Keep blobs only; submodules (commit entries) are not files.
            if kind == Some(b"blob")
                && let Some(oid) = oid
            {
                map.insert(path.to_vec(), String::from_utf8_lossy(oid).into_owned());
            }
        }
        Ok(map)
    }

    pub(super) fn head_exists(&self) -> Result<bool> {
        let out = Command::new("git")
            .current_dir(&self.path)
            .args(["rev-parse", "--verify", "--quiet", "HEAD"])
            .output()?;
        Ok(out.status.success())
    }
}

#[cfg(test)]
mod tests {
    use path_absolutize::Absolutize;

    use super::*;
    use crate::{crypt::HEADER_LEN, repo::init_temp_repo};

    /// Coverage must be prefix-exact on path-component boundaries: an entry
    /// names a file or an ancestor directory, never a string prefix.
    #[test]
    fn test_crypt_coverage_prefix_boundaries() {
        let coverage = CryptCoverage::new(&["secret.txt".to_string(), "docs".to_string()]);

        assert!(coverage.covers("secret.txt"));
        assert!(coverage.covers("docs"));
        assert!(coverage.covers("docs/a/b.md"));
        // Longer names sharing the prefix are different components.
        assert!(!coverage.covers("docsx"));
        assert!(!coverage.covers("docsx/a.md"));
        assert!(!coverage.covers("other.txt"));
        // An empty crypt list covers nothing.
        assert!(!CryptCoverage::new(&[]).covers("docs/a.md"));
    }

    /// Write `bytes` into the object store of the repo at `repo_path` and
    /// return the printed blob oid.
    fn hash_object(repo_path: &Path, bytes: &[u8]) -> Result<String> {
        use std::process::Stdio;

        let mut child = Command::new("git")
            .current_dir(repo_path)
            .args(["hash-object", "-w", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(bytes)?;
        // EOF before git prints the oid.
        drop(stdin);
        let out = child.wait_with_output()?;
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }

    /// Read a whole blob payload through the stream interface (the mirror of
    /// the former whole-blob `blob` method, exercising `read_exact` over the
    /// full payload).
    fn read_full(batch: &mut CatFileBatch, oid: &str) -> Result<Option<Vec<u8>>> {
        let Some(mut stream) = batch.blob_stream(oid)? else {
            return Ok(None);
        };
        let mut buf = vec![0u8; stream.len()];
        stream.read_exact(&mut buf)?;
        stream.skip_to_end()?;
        Ok(Some(buf))
    }

    /// `blob_prefix` drains exactly the unread payload.
    ///
    /// Across any mix of prefix reads, full reads and missing-object
    /// responses, the session stays aligned and later responses still
    /// parse. Covers the exact `HEADER_LEN` boundary (prefix covers the
    /// whole payload, only the LF gets drained) and blobs smaller than the
    /// prefix.
    #[test]
    fn test_cat_file_batch_prefix_keeps_session_aligned() -> Result<()> {
        let dir = init_temp_repo();
        let repo_path = dir.path().absolutize()?.to_path_buf();

        let big: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let big_oid = hash_object(&repo_path, &big)?;
        let edge: Vec<u8> = (0..HEADER_LEN)
            .map(u8::try_from)
            .collect::<Result<_, _>>()
            .unwrap();
        let edge_oid = hash_object(&repo_path, &edge)?;
        let small = b"tiny blob".to_vec();
        let small_oid = hash_object(&repo_path, &small)?;

        let mut batch = CatFileBatch::spawn(&repo_path)?;
        let head = batch.blob_prefix(&big_oid, HEADER_LEN)?.unwrap();
        assert_eq!(head, &big[..HEADER_LEN]);

        let head = batch.blob_prefix(&edge_oid, HEADER_LEN)?.unwrap();
        assert_eq!(head, edge);

        // A missing object between two hits must not shift the framing.
        assert!(
            batch
                .blob_prefix("0000000000000000000000000000000000000000", HEADER_LEN)?
                .is_none()
        );

        let head = batch.blob_prefix(&small_oid, HEADER_LEN)?.unwrap();
        assert_eq!(head, small);

        // Full reads still work after all the prefix reads.
        assert_eq!(read_full(&mut batch, &big_oid)?, Some(big));
        assert_eq!(read_full(&mut batch, &small_oid)?, Some(small));
        Ok(())
    }
}
