//! Install/uninstall-time working-tree migration analysis and execution.
//!
//! [`Repo::migration_plan`] classifies the tracked crypt-list files at
//! install time; [`Repo::force_recheckout`] re-checkouts paths through the
//! currently configured filters; [`Repo::clean_crypt_paths`] splits the
//! tracked files into clean (safe to reset) and dirty (keep the worktree
//! copy) at uninstall time.

use std::{collections::HashSet, process::Command};

use log::warn;

use super::{
    Repo,
    git::{CatFileBatch, CompareOutcome, CryptCoverage, nul_records, read_prefix, stream_eq_file},
};
use crate::{
    crypt::HEADER_LEN,
    error::{Error, Result},
    filter::is_ciphertext,
};

impl Repo {
    /// Split the tracked crypt-list files into (clean, dirty) relative to
    /// HEAD, compared through the currently configured clean filter. Clean
    /// files are safe to force-checkout back to their raw ciphertext blobs
    /// once the filters are removed; dirty files carry staged or unstaged
    /// changes and must keep their worktree copy.
    pub(super) fn clean_crypt_paths(&self) -> Result<(Vec<String>, Vec<String>)> {
        let mut candidates = Vec::new();
        if !self.conf.crypt_list.is_empty() && self.head_exists()? {
            let head = self.head_tree_blobs()?;
            if !head.is_empty() {
                let coverage = CryptCoverage::new(&self.conf.crypt_list);
                let index = self.index_blobs()?;
                candidates = head
                    .keys()
                    // Only files that are both committed and still tracked;
                    // a staged deletion must not resurface through the tree.
                    .filter(|p| index.contains_key(*p))
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .filter(|rel| coverage.covers(rel))
                    .collect();
            }
        }

        // `git diff --name-only -z HEAD` lists everything that differs from
        // HEAD (staged and unstaged alike), so staged changes can never be
        // reset by the later force-checkout. One chunked invocation covers
        // any file count, unlike a per-file `git diff --quiet`.
        let mut dirty = HashSet::new();
        for chunk in candidates.chunks(64) {
            let mut args: Vec<&str> = vec!["diff", "--name-only", "-z", "HEAD", "--"];
            args.extend(chunk.iter().map(String::as_str));
            for path in nul_records(&self.run_with_output_bytes(&args)?) {
                dirty.insert(String::from_utf8_lossy(path).into_owned());
            }
        }
        Ok(candidates.into_iter().partition(|rel| !dirty.contains(rel)))
    }

    /// Transcrypt-style migration analysis at install time, over tracked
    /// crypt-list files whose worktree copy still equals the committed blob
    /// byte-for-byte (typical right after a clone, before any filter was
    /// installed). See [`MigrationPlan`] for the outcomes; executing the
    /// plan happens in [`Repo::execute_migration`].
    ///
    /// Unlike the pre-refactor code (one `git cat-file` spawn per file), the
    /// HEAD blobs are streamed through a single [`CatFileBatch`] session and
    /// compared chunk-by-chunk against the worktree files: a size mismatch
    /// classifies without reading the file body, and a matching size stops
    /// at the first differing chunk. No side of the compare is ever held in
    /// memory in full.
    pub(super) fn migration_plan(&self) -> Result<MigrationPlan> {
        let mut plan = MigrationPlan::default();
        if self.conf.crypt_list.is_empty() {
            return Ok(plan);
        }
        let head = self.head_tree_blobs()?;
        if head.is_empty() {
            return Ok(plan); // unborn branch: nothing committed to migrate
        }
        let index = self.index_blobs()?;
        let coverage = CryptCoverage::new(&self.conf.crypt_list);
        let mut batch = CatFileBatch::spawn(&self.path)?;
        for (path, oid) in &head {
            // Only files that are both committed and still tracked; a staged
            // deletion must not resurface through the tree side.
            if !index.contains_key(path) {
                continue;
            }
            let rel = String::from_utf8_lossy(path).into_owned();
            if !coverage.covers(&rel) {
                continue;
            }
            let Some(mut stream) = batch.blob_stream(oid)? else {
                continue;
            };
            // The header prefix decides both magic checks; the payload body
            // is only consumed when a full compare is actually needed.
            let mut blob_head = vec![0u8; HEADER_LEN.min(stream.len())];
            stream.read_exact(&mut blob_head)?;
            let blob_encrypted = is_ciphertext(&blob_head);

            // A worktree copy is unreadable not only when the open fails but
            // also when its reads do (e.g. the path was replaced by a
            // directory: Unix opens it fine and fails the first read with
            // EISDIR); both classify the same way. Blob-side errors stay
            // `?` — a broken batch session is fatal, an unreadable file is
            // not.
            let opened = std::fs::File::open(self.path.join(&rel))
                .and_then(|file| file.metadata().map(|meta| (file, meta.len())));
            let compared = 'worktree: {
                let Ok((mut file, file_len)) = opened else {
                    break 'worktree None;
                };
                // One prefix read feeds both the worktree magic check and
                // the first compare segment.
                let mut file_head = vec![0u8; blob_head.len()];
                let Ok(filled) = read_prefix(&mut file, &mut file_head) else {
                    break 'worktree None;
                };
                let worktree_encrypted = is_ciphertext(&file_head[..filled]);
                if file_len != stream.len() as u64
                    || filled != blob_head.len()
                    || file_head != blob_head
                {
                    break 'worktree Some((false, worktree_encrypted));
                }
                match stream_eq_file(&mut stream, &mut file)? {
                    CompareOutcome::Equal => Some((true, worktree_encrypted)),
                    CompareOutcome::Different => Some((false, worktree_encrypted)),
                    CompareOutcome::FileUnreadable => None,
                }
            };
            let Some((equal, worktree_encrypted)) = compared else {
                // An unreadable worktree copy has nothing to compare
                // against; drain the unconsumed payload so the cat-file
                // session stays aligned for the next file.
                stream.skip_to_end()?;
                if !blob_encrypted {
                    plan.needs_renormalize = true;
                }
                continue;
            };
            stream.skip_to_end()?;

            if equal {
                // untouched since the last checkout: safe to re-smudge
                if blob_encrypted {
                    plan.to_decrypt.push(rel);
                } else {
                    // committed as plaintext before the filter existed
                    plan.needs_renormalize = true;
                }
            } else if blob_encrypted && !worktree_encrypted {
                // decrypted outside git (e.g. `git-se d`): the cached stat
                // no longer matches; renormalize refreshes it losslessly
                plan.needs_renormalize = true;
            } else if !blob_encrypted {
                // committed as plaintext before the filter existed
                plan.needs_renormalize = true;
            }
        }
        Ok(plan)
    }

    /// Run the force-checkout migration selected by `plan`: delete the
    /// worktree copies and `git checkout --force HEAD` them back so the
    /// smudge filter decrypts them. Returns the number of files decrypted.
    pub(super) fn execute_migration(&self, plan: &MigrationPlan) -> usize {
        self.force_recheckout(&plan.to_decrypt, "install")
    }

    /// Delete the worktree copies of `paths` and `git checkout --force HEAD`
    /// them back, whatever that yields with the currently configured
    /// filters (smudge installed → plaintext, no filters → raw ciphertext
    /// blobs). `context` names the calling command in warnings. Returns the
    /// number of files restored.
    pub(super) fn force_recheckout(&self, paths: &[String], context: &str) -> usize {
        // Chunk to stay clear of argv length limits on huge crypt lists.
        let mut restored = 0;
        'chunks: for chunk in paths.chunks(64) {
            for rel in chunk {
                let _ = std::fs::remove_file(self.path.join(rel));
            }
            let mut args: Vec<&str> = vec!["checkout", "--force", "HEAD", "--"];
            args.extend(chunk.iter().map(String::as_str));
            match Command::new("git")
                .current_dir(&self.path)
                .args(&args)
                .output()
            {
                Ok(out) if out.status.success() => restored += chunk.len(),
                Ok(out) => {
                    warn!(
                        "git checkout failed during {context}: {}",
                        String::from_utf8_lossy(&out.stderr)
                    );
                    break 'chunks;
                },
                Err(e) => {
                    warn!("failed to run git checkout during {context}: {e}");
                    break 'chunks;
                },
            }
        }
        restored
    }

    /// Whether any of `paths` (repo-relative) differ between the index and
    /// HEAD, via `git diff --cached --quiet`: exit code 1 means differences
    /// exist, 0 means none.
    pub(super) fn has_staged_changes(&self, paths: &[String]) -> Result<bool> {
        for chunk in paths.chunks(64) {
            let out = Command::new("git")
                .current_dir(&self.path)
                .args(["diff", "--cached", "--quiet", "--"])
                .args(chunk)
                .output()?;
            match out.status.code() {
                Some(0) => {},
                Some(1) => return Ok(true),
                _ => {
                    return Err(Error::Git(
                        String::from_utf8_lossy(&out.stderr).into_owned(),
                    ));
                },
            }
        }
        Ok(false)
    }
}

/// Install-time migration analysis of the tracked crypt files (the
/// transcrypt-style re-smudge performed by [`Repo::install_filter`]).
#[derive(Default)]
pub(super) struct MigrationPlan {
    /// Tracked crypt files whose worktree copy still equals the committed
    /// (encrypted) blob byte-for-byte — safe to delete and force-checkout so
    /// the smudge filter decrypts them.
    pub(super) to_decrypt: Vec<String>,
    /// Whether `git add --renormalize .` should be recommended afterwards:
    /// some blob was committed as plaintext before the filter existed, or
    /// some file was decrypted outside of git and its cached stat is stale.
    pub(super) needs_renormalize: bool,
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use path_absolutize::Absolutize;

    use super::*;
    use crate::{
        crypt::{HEADER_LEN, VERSION},
        repo::init_temp_repo,
    };

    /// A 64-byte header that `is_ciphertext` recognizes: magic, current
    /// version, known algorithm (1 = XChaCha20-Poly1305).
    fn fake_ciphertext_header() -> Vec<u8> {
        let mut header = vec![0u8; HEADER_LEN];
        header[..5].copy_from_slice(b"GITSE");
        header[5] = VERSION;
        header[7] = 1;
        header
    }

    /// The streamed migration compare must catch differences behind the
    /// shared 64-byte header.
    ///
    /// One byte different late in the body (equal size), an extra tail and a
    /// truncation all classify without landing in `to_decrypt`, while the
    /// byte-for-byte equal copy does.
    #[test]
    fn test_migration_plan_streamed_compare_edges() -> Result<()> {
        let dir = init_temp_repo();
        let repo_path = dir.path().absolutize()?.to_path_buf();
        let mut repo = Repo::open(&repo_path)?;

        // Every variant starts as the same committed ciphertext; the edits
        // below then diverge only the worktree copies, all behind the
        // shared 64-byte header.
        let mut blob = fake_ciphertext_header();
        blob.extend((0..200u32).map(|i| (i % 251) as u8));

        for name in ["same.bin", "mid.bin", "longer.bin", "shorter.bin"] {
            std::fs::write(repo_path.join(name), &blob)?;
            repo.conf.add_one_path_to_crypt_list(name)?;
        }

        repo.run(&["add", "same.bin", "mid.bin", "longer.bin", "shorter.bin"])?;
        let out = Command::new("git")
            .current_dir(&repo_path)
            .args([
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-m",
                "init",
            ])
            .output()?;
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );

        // Worktree-only edits after the commit: one byte different late in
        // the body (equal size), one extra tail, one truncation.
        let mut mid = blob.clone();
        *mid.last_mut().unwrap() ^= 0xff;
        std::fs::write(repo_path.join("mid.bin"), &mid)?;
        let mut longer = blob.clone();
        longer.push(0);
        std::fs::write(repo_path.join("longer.bin"), &longer)?;
        std::fs::write(repo_path.join("shorter.bin"), &blob[..blob.len() - 1])?;

        let plan = repo.migration_plan()?;
        // The variants keep their ciphertext headers, so besides missing the
        // equality they match none of the renormalize cases either.
        assert_eq!(plan.to_decrypt, ["same.bin"]);
        assert!(!plan.needs_renormalize);
        Ok(())
    }

    /// A worktree path that cannot be read must classify the file as
    /// unreadable instead of failing the whole plan, exactly like an
    /// unopenable one.
    ///
    /// A directory in place of the tracked file exercises the read-failure
    /// fold on Unix (open succeeds, the first read fails with EISDIR) and
    /// the unopenable branch on Windows. Either way the file is skipped:
    /// not in `to_decrypt`, but its plaintext blob still asks for
    /// renormalize.
    #[test]
    fn test_migration_plan_unreadable_worktree_is_skipped() -> Result<()> {
        let dir = init_temp_repo();
        let repo_path = dir.path().absolutize()?.to_path_buf();
        let mut repo = Repo::open(&repo_path)?;

        // One ciphertext and one plaintext blob, each with a healthy twin
        // that must keep classifying normally.
        let mut cipher = fake_ciphertext_header();
        cipher.extend(0..64u8);
        for (name, bytes) in [
            ("enc.bin", cipher.as_slice()),
            ("enc_ok.bin", cipher.as_slice()),
            ("plain.bin", b"plaintext\n".as_slice()),
        ] {
            std::fs::write(repo_path.join(name), bytes)?;
            repo.conf.add_one_path_to_crypt_list(name)?;
        }

        repo.run(&["add", "enc.bin", "enc_ok.bin", "plain.bin"])?;
        let out = Command::new("git")
            .current_dir(&repo_path)
            .args([
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-m",
                "init",
            ])
            .output()?;
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );

        // Replace one file of each blob kind by a directory.
        for name in ["enc.bin", "plain.bin"] {
            std::fs::remove_file(repo_path.join(name))?;
            std::fs::create_dir(repo_path.join(name))?;
        }

        let plan = repo.migration_plan()?;
        assert_eq!(plan.to_decrypt, ["enc_ok.bin"]);
        // The unreadable plaintext blob keeps the renormalize hint.
        assert!(plan.needs_renormalize);
        Ok(())
    }
}
