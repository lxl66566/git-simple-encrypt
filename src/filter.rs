//! Git filter-driver entry points (transcrypt-style integration).
//!
//! [`install`](crate::repo::Repo::install_filter) wires git to these commands:
//!
//! | git callback | config key | behavior |
//! |---|---|---|
//! | clean | `filter.git-se.clean` | `git add`/`git status`: stdin plaintext → stdout ciphertext |
//! | smudge | `filter.git-se.smudge` | checkout: stdin ciphertext → stdout plaintext; records the salt cache |
//! | textconv | `diff.git-se.textconv` | `git diff`/`git log -p`: decrypts the blob temp file given as argv |
//!
//! Idempotency: clean passes already-encrypted input through unchanged and
//! smudge passes non-encrypted input through unchanged, mirroring the skip
//! behavior of the manual `e`/`d` commands. This keeps the manual and filter
//! workflows composable and makes migration safe (a worktree holding
//! ciphertext from the manual workflow stays consistent with the index).
//!
//! Header sniffing is asymmetric on purpose (see `crypt::Sniffed`): clean
//! never encrypts over any GITSE-magic file (a future format version passes
//! through untouched instead of being double-wrapped), while smudge refuses
//! GITSE files it cannot decrypt with an explicit error rather than handing
//! the ciphertext to the worktree as fake plaintext.
//!
//! Determinism: git re-runs clean after a mere `touch`, and a different
//! ciphertext would surface as a phantom modification. `clean` therefore
//! reuses the cached `(salt, file_id)` for the path — recording a fresh one
//! before encrypting on first use — and `smudge` records the entry of the
//! blob it just checked out, so a checkout + re-add cycle reproduces the
//! identical blob. `diff` never records: textconv also runs on *old* blobs
//! (`git log -p`), and a stale entry would make the next clean diverge from
//! the index.

use std::{
    io::{self, BufWriter, Read, Write},
    path::Path,
};

use log::warn;
use rand::prelude::Rng;

use crate::{
    crypt::{
        self, FileHeader, HEADER_LEN, SALT_LEN, Sniffed, cache_key, derive_key, encrypt_into, sniff,
    },
    error::Result,
    repo::Repo,
    salt_cache::{self, CachedEntry, SaltCacheReader},
};

/// Read up to `n` bytes from `reader`, returning exactly what was consumed
/// (fewer only at EOF). The caller replays these bytes ahead of the stream.
fn peek(reader: &mut dyn Read, n: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let mut filled = 0;
    while filled < n {
        match reader.read(&mut buf[filled..])? {
            0 => break,
            k => filled += k,
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

/// Whether `buf` starts with a full, recognized GITSE header: magic,
/// supported version, and a known encryption algorithm.
///
/// The `enc_algo` check matters: without it a plaintext crafted to start with
/// `GITSE\x03` would pass clean's passthrough gate and enter the repository
/// unencrypted.
pub(crate) fn is_ciphertext(buf: &[u8]) -> bool {
    buf.first_chunk::<HEADER_LEN>()
        .is_some_and(|bytes| matches!(sniff(bytes), Sniffed::Ciphertext))
}

/// Write `prefix` followed by the rest of `reader` unchanged.
fn passthrough(prefix: &[u8], reader: &mut dyn Read, out: &mut dyn Write) -> Result<()> {
    out.write_all(prefix)?;
    io::copy(reader, out)?;
    out.flush()?;
    Ok(())
}

/// Clean filter core: encrypt the stream. Already-encrypted input passes
/// through unchanged (idempotent).
fn clean_stream<W: Write>(
    repo: &Repo,
    path: &Path,
    input: &mut dyn Read,
    out: &mut W,
) -> Result<()> {
    let prefix = peek(input, HEADER_LEN)?;
    match prefix
        .first_chunk::<HEADER_LEN>()
        .map_or(Sniffed::Plaintext, sniff)
    {
        // Recognized ciphertext passes through unchanged (idempotency). A
        // future-version GITSE file passes through too: encrypting over it
        // would double-wrap data that no current build can unwrap in one
        // step, so it is left byte-identical instead.
        Sniffed::Ciphertext | Sniffed::FutureVersion(_) => {
            return passthrough(&prefix, input, out);
        },
        Sniffed::UnknownAlgo(algo) => {
            warn!("GITSE magic with unknown algorithm byte {algo}; encrypting as plaintext");
        },
        Sniffed::Plaintext => {},
    }

    let password = repo.get_key()?;
    let key = cache_key(path, repo.path());
    let reader = SaltCacheReader::load(repo.path());
    let (salt, file_id) = reader.get(&key).map_or_else(
        || {
            // First clean of this path: mint an entry and record it
            // atomically under the cache lock, so concurrent first-cleans of
            // the same path converge on ONE entry instead of
            // last-writer-wins (the loser's ciphertext would otherwise
            // diverge from the cache and resurface as a phantom
            // modification on the next clean).
            let candidate = CachedEntry {
                salt: random_salt(),
                file_id: FileHeader::generate_file_id(),
            };
            let entry = salt_cache::resolve_or_insert(repo.path(), &key, candidate);
            (entry.salt, Some(entry.file_id))
        },
        |entry| (entry.salt, Some(entry.file_id)),
    );

    let derived_key = derive_key(password.as_bytes(), &salt)?;
    let mut stream = io::Cursor::new(prefix).chain(input);
    encrypt_into(
        &mut stream,
        out,
        &derived_key,
        salt,
        file_id,
        repo.conf.use_zstd.then_some(repo.conf.zstd_level),
    )?;
    out.flush()?;
    Ok(())
}

/// Decrypt-stream core shared by smudge and diff.
///
/// Non-encrypted input passes through unchanged. `record_key`, when given,
/// persists the header entry for deterministic re-encryption (smudge only,
/// see module docs).
fn decrypt_stream<W: Write>(
    repo: &Repo,
    input: &mut dyn Read,
    out: &mut W,
    record_key: Option<&[u8]>,
) -> Result<()> {
    let prefix = peek(input, HEADER_LEN)?;
    match prefix
        .first_chunk::<HEADER_LEN>()
        .map_or(Sniffed::Plaintext, sniff)
    {
        Sniffed::Plaintext => return passthrough(&prefix, input, out),
        // A GITSE file this build cannot handle fails loudly: silently
        // passing the ciphertext through would hand it to the worktree as
        // fake "plaintext" (and via `filter.required=true`, git aborts the
        // whole operation so the mismatch cannot go unnoticed).
        Sniffed::FutureVersion(v) => return Err(crate::error::Error::UnsupportedVersion(v)),
        Sniffed::UnknownAlgo(a) => return Err(crate::error::Error::UnsupportedAlgo(a)),
        Sniffed::Ciphertext => {},
    }

    let password = repo.get_key()?;
    let mut stream = io::Cursor::new(prefix).chain(input);
    let header = crypt::decrypt_into(&mut stream, out, password.as_bytes())?;
    out.flush()?;

    if let Some(key) = record_key {
        salt_cache::merge_entries(repo.path(), [(key.to_vec(), CachedEntry {
            salt: header.salt,
            file_id: header.file_id,
        })]);
    }
    Ok(())
}

fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    salt
}

/// Git clean filter: encrypt stdin to stdout. `path` is the `%f` placeholder,
/// the file path relative to the repo root.
pub fn clean(repo: &Repo, path: &Path) -> Result<()> {
    let mut stdin = io::stdin().lock();
    let mut stdout = BufWriter::new(io::stdout().lock());
    clean_stream(repo, path, &mut stdin, &mut stdout)
}

/// Git smudge filter: decrypt stdin to stdout and record the salt cache.
pub fn smudge(repo: &Repo, path: &Path) -> Result<()> {
    let key = cache_key(path, repo.path());
    let mut stdin = io::stdin().lock();
    let mut stdout = BufWriter::new(io::stdout().lock());
    decrypt_stream(repo, &mut stdin, &mut stdout, Some(&key))
}

/// Diff textconv: decrypt the ciphertext blob in `file` (the temp file git
/// passes as argv) to stdout; reads stdin when `file` is omitted.
pub fn diff(repo: &Repo, file: Option<&Path>) -> Result<()> {
    let mut stdout = BufWriter::new(io::stdout().lock());
    let Some(path) = file else {
        let mut stdin = io::stdin().lock();
        return decrypt_stream(repo, &mut stdin, &mut stdout, None);
    };
    let mut input = std::fs::File::open(path)?;
    decrypt_stream(repo, &mut input, &mut stdout, None)
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, process::Command};

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

    fn clean_into(repo: &Repo, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut input = Cursor::new(data.to_vec());
        clean_stream(repo, Path::new("f.txt"), &mut input, &mut out).unwrap();
        out
    }

    fn decrypt_into_buf(repo: &Repo, data: &[u8], record: Option<&[u8]>) -> Vec<u8> {
        let mut out = Vec::new();
        let mut input = Cursor::new(data.to_vec());
        decrypt_stream(repo, &mut input, &mut out, record).unwrap();
        out
    }

    #[test]
    fn test_clean_smudge_roundtrip_and_cache() {
        let (_dir, repo) = init_repo();

        let ciphertext = clean_into(&repo, b"plain");
        assert!(is_ciphertext(&ciphertext));

        // smudge records the salt cache entry under the path key
        let plaintext = decrypt_into_buf(&repo, &ciphertext, Some(b"f.txt"));
        assert_eq!(plaintext, b"plain");
        let reader = SaltCacheReader::load(repo.path());
        assert!(reader.get(b"f.txt").is_some());

        // clean now reuses the cached entry: byte-identical output
        assert_eq!(clean_into(&repo, b"plain"), ciphertext);
    }

    #[test]
    fn test_clean_is_idempotent_on_ciphertext() {
        let (_dir, repo) = init_repo();
        let ciphertext = clean_into(&repo, b"secret");
        // re-cleaning ciphertext must return it unchanged, not double-encrypt
        assert_eq!(clean_into(&repo, &ciphertext), ciphertext);
    }

    #[test]
    fn test_decrypt_passthrough_on_plaintext_and_short_input() {
        let (_dir, repo) = init_repo();
        assert_eq!(
            decrypt_into_buf(&repo, b"not encrypted", None),
            b"not encrypted"
        );
        assert_eq!(decrypt_into_buf(&repo, b"ab", None), b"ab");
        assert_eq!(decrypt_into_buf(&repo, b"", None), b"");
    }

    #[test]
    fn test_decrypt_wrong_password_fails() {
        let (_dir, repo) = init_repo();
        let ciphertext = clean_into(&repo, b"secret");
        repo.set_config("key", "other").unwrap();
        let mut out = Vec::new();
        let mut input = Cursor::new(ciphertext);
        // failure propagates as a non-zero exit, making git abort the operation
        assert!(decrypt_stream(&repo, &mut input, &mut out, None).is_err());
    }

    /// A file with valid magic+version but a bogus algorithm byte: plaintext
    /// imitating our header must be encrypted, not passed through into the
    /// index.
    #[test]
    fn test_clean_encrypts_fake_gitse_header_with_unknown_algo() {
        let (_dir, repo) = init_repo();

        let mut fake = vec![0u8; HEADER_LEN + 10];
        fake[..5].copy_from_slice(b"GITSE");
        fake[5] = 3; // current version
        fake[7] = 0x7f; // unknown algorithm
        fake[HEADER_LEN..].copy_from_slice(b"plaintext!");

        assert!(!is_ciphertext(&fake));

        let out = clean_into(&repo, &fake);
        assert_ne!(out, fake);
        assert!(is_ciphertext(&out));
        assert_eq!(decrypt_into_buf(&repo, &out, None), fake);
    }

    /// A GITSE file of a future version is never double-wrapped by clean and
    /// is rejected loudly by smudge instead of being handed to the worktree
    /// as fake plaintext.
    #[test]
    fn test_future_version_passthrough_on_clean_and_smudge_error() {
        let (_dir, repo) = init_repo();

        let mut future = vec![0u8; HEADER_LEN + 10];
        future[..5].copy_from_slice(b"GITSE");
        future[5] = 4; // future version
        future[7] = 1;
        future[HEADER_LEN..].copy_from_slice(b"ciphertext");

        // clean passes it through byte-identically
        assert_eq!(clean_into(&repo, &future), future);

        // smudge refuses with an explicit unsupported-version error
        let mut out = Vec::new();
        let mut input = Cursor::new(future);
        let err = decrypt_stream(&repo, &mut input, &mut out, None).unwrap_err();
        assert!(matches!(err, crate::error::Error::UnsupportedVersion(4)));
    }
}
