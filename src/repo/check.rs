//! The `check` command family: verifying that crypt-list files are
//! encrypted, in the worktree or among the staged blobs.

use std::path::PathBuf;

use log::warn;
use parking_lot::Mutex;

use super::{Repo, git::CatFileBatch};
use crate::{
    crypt::HEADER_LEN,
    error::{Error, Result},
    filter::is_ciphertext,
    utils::{Progress, is_file_encrypted, parallel, resolve_target_files, style::Colorize},
};

impl Repo {
    /// Check if all files in the crypt list (or given paths) are encrypted.
    ///
    /// When `staged` is true, only files staged for the current commit are
    /// checked, and their *staged blobs* are inspected — the blob is what
    /// the commit would actually write, so a worktree file that was
    /// encrypted, edited or deleted after staging cannot mask a staged
    /// plaintext (see [`Repo::check_staged`]). This is the mode the
    /// pre-commit hook uses.
    ///
    /// Returns `Ok(())` if all files are encrypted, or an error summarizing
    /// which files are not encrypted. The process exits with a non-zero code
    /// when files are not encrypted, suitable for CI usage.
    pub fn check(&self, paths: &[PathBuf], staged: bool) -> Result<()> {
        // In filter mode the working tree stays plaintext by design, so
        // checking worktree files would always fail and report nothing
        // useful. The staged check stays meaningful: it inspects the staged
        // blobs that will actually be committed.
        let filter_mode = self.filter_installed();
        if filter_mode && !staged {
            println!(
                "Filter integration is active: working-tree files stay plaintext and are \
                 encrypted automatically by git; only `check --staged` is meaningful (it inspects \
                 the staged blobs)."
            );
            return Ok(());
        }

        if staged {
            return self.check_staged();
        }

        let target_files = resolve_target_files(paths, &self.conf.crypt_list, self.path());
        if target_files.is_empty() {
            return Err(Error::NoFile("check"));
        }
        self.check_worktree(&target_files)
    }

    /// `check --staged`: inspect the staged blobs of crypt-list files.
    ///
    /// Enumeration uses `git diff --cached --name-only -z` (raw NUL-separated
    /// paths: `-z` disables C-quoting, so paths with `"`, backslashes,
    /// spaces or non-ASCII survive byte-for-byte) and membership is a plain
    /// prefix test against the crypt list. Blob contents come from
    /// `git ls-files -s` oids through a single [`CatFileBatch`] session —
    /// never from a per-file `exists()` worktree check, which used to drop
    /// staged files whose worktree copy had been deleted (F7a) and masked
    /// staged plaintext under an already-encrypted worktree file.
    fn check_staged(&self) -> Result<()> {
        let targets = self.staged_crypt_blobs()?;
        if targets.is_empty() {
            println!("No staged files need encryption check.");
            return Ok(());
        }

        println!(
            "\n{} {} {}",
            "Checking encryption status".bold(),
            format!("({} files)", targets.len()).cyan(),
            ":".dimmed()
        );

        let pb = Progress::new(targets.len(), "Check");
        let mut not_encrypted: Vec<String> = Vec::new();
        let mut first_error: Option<Error> = None;
        let mut batch = CatFileBatch::spawn(&self.path)?;
        for (rel, oid) in &targets {
            // The magic check only needs the leading header bytes; the rest
            // of the payload is drained without buffering, so staged blobs
            // of any size cost a fixed ~64-byte allocation.
            match batch.blob_prefix(oid, HEADER_LEN) {
                Ok(Some(head)) => {
                    if !is_ciphertext(&head) {
                        not_encrypted.push(rel.clone());
                    }
                },
                Ok(None) => warn!("staged blob {oid} of {rel} is missing from the object store"),
                Err(e) => {
                    warn!("Failed to read staged blob of {rel}: {e}");
                    first_error.get_or_insert(e);
                },
            }
            pb.inc(1);
        }
        pb.finish_and_clear();

        // Every error was logged above; surface the first one as the return value.
        if let Some(first) = first_error {
            return Err(first);
        }
        report_check(&not_encrypted, targets.len())
    }

    /// Check worktree files (manual/hook mode; filter mode never gets here).
    fn check_worktree(&self, target_files: &[PathBuf]) -> Result<()> {
        println!(
            "\n{} {} {}",
            "Checking encryption status".bold(),
            format!("({} files)", target_files.len()).cyan(),
            ":".dimmed()
        );

        let pb = Progress::new(target_files.len(), "Check");
        let not_encrypted: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let errors: Mutex<Vec<Error>> = Mutex::new(Vec::new());

        parallel::for_each(target_files, |f| {
            match is_file_encrypted(f) {
                Ok(false) => {
                    let mut list = not_encrypted.lock();
                    let relative = pathdiff::diff_paths(f, &self.path).unwrap_or_else(|| f.clone());
                    list.push(relative.display().to_string());
                },
                Ok(true) => {},
                Err(e) => {
                    warn!("Failed to check {}: {e}", f.display());
                    errors.lock().push(e);
                },
            }
            pb.inc(1);
        });

        // Clear the progress bar on every exit path, error or not.
        pb.finish_and_clear();

        // Every error was logged above; surface the first one as the return value.
        if let Some(first) = errors.into_inner().into_iter().next() {
            return Err(first);
        }
        report_check(&not_encrypted.into_inner(), target_files.len())
    }
}

/// Print the check summary; `Err(FilesNotEncrypted)` when anything is plain.
fn report_check(not_encrypted: &[String], total: usize) -> Result<()> {
    if not_encrypted.is_empty() {
        println!(
            "\n{}: All {} files are encrypted.",
            "Check complete".bold(),
            total.to_string().green(),
        );
        return Ok(());
    }

    println!(
        "\n{} files are {}:",
        not_encrypted.len().to_string().yellow(),
        "NOT encrypted".yellow()
    );
    for f in not_encrypted {
        println!("  - {f}");
    }

    println!(
        "\n{}: {}/{} files encrypted",
        "Check complete".bold(),
        (total - not_encrypted.len()).to_string().green(),
        total,
    );

    Err(Error::FilesNotEncrypted(not_encrypted.len(), total))
}

#[cfg(test)]
mod tests {
    use path_absolutize::Absolutize;

    use super::*;
    use crate::repo::init_temp_repo;

    #[test]
    fn test_check_reports_unencrypted() -> Result<()> {
        let dir = init_temp_repo();
        let repo_path = dir.path().absolutize().unwrap().to_path_buf();
        let mut repo = Repo::open(&repo_path)?;

        // Add a plaintext file to the crypt list.
        std::fs::write(repo_path.join("plain.txt"), b"hello")?;
        repo.conf.add_one_path_to_crypt_list("plain.txt")?;

        // check should return FilesNotEncrypted.
        let result = repo.check(&[], false);
        assert!(matches!(result, Err(Error::FilesNotEncrypted(1, 1))));

        // Encrypt the file (cheap path: just give it a valid 64-byte GITSE header so
        // is_file_encrypted returns true), then check passes. The algorithm
        // byte must be valid too: a magic-only header with an unknown
        // algorithm byte is plaintext imitating the format and check must
        // flag it.
        let mut fake_header = vec![0u8; HEADER_LEN];
        fake_header[..5].copy_from_slice(b"GITSE");
        fake_header[5] = 3; // version
        fake_header[7] = 1; // enc_algo
        std::fs::write(repo_path.join("plain.txt"), fake_header).unwrap();
        let result = repo.check(&[], false);
        assert!(result.is_ok());
        Ok(())
    }
}
