//! Installing and uninstalling the git filter integration.
//!
//! `install_filter` wires the clean/smudge/process filter drivers, the diff
//! textconv and the managed `.gitattributes` block, then runs the
//! install-time migration; `uninstall` removes them and restores the
//! ciphertext working-tree copies.

use log::warn;

use super::{
    Repo,
    hooks::{is_managed_hook, quote_exe_for_sh},
};
use crate::{
    error::{Error, Result},
    gitattributes,
    utils::{atomic_write, style::Colorize},
};

impl Repo {
    /// Install the git filter integration: export `.gitattributes` and
    /// configure the clean/smudge filter driver plus the plaintext-diff
    /// textconv (transcrypt-style). After this, encryption and decryption
    /// are driven by git itself and the working tree stays plaintext.
    ///
    /// A git-se managed pre-commit hook is removed: it checks worktree
    /// files, which are plaintext on purpose in filter mode, so it would
    /// block every commit. Foreign hooks are kept (a warning is printed).
    pub fn install_filter(&self) -> Result<()> {
        // 0. Analyze the install-time migration before touching anything. Its `git checkout --force
        //    HEAD -- <paths>` resets the index as well as the worktree, so staged user changes on
        //    the affected paths must be surfaced as a hard error instead of being silently
        //    discarded.
        let has_key = self.get_key().is_ok();
        let plan = if has_key {
            Some(self.migration_plan()?)
        } else {
            None
        };
        if let Some(plan) = &plan
            && !plan.to_decrypt.is_empty()
            && self.has_staged_changes(&plan.to_decrypt)?
        {
            return Err(Error::Other(format!(
                "install would reset {} staged crypt-list file(s) via `git checkout --force HEAD \
                 --` (it rewrites the index too); commit them first or unstage them (`git restore \
                 --staged <path>`), then re-run install",
                plan.to_decrypt.len()
            )));
        }

        // Absolute exe path survives PATH changes; forward slashes work in
        // both POSIX sh and MSYS sh; single quotes make it shell-safe.
        let exe = std::env::current_exe()
            .map_err(|e| Error::Other(format!("failed to locate the running executable: {e}")))?;
        let quoted = quote_exe_for_sh(&exe);

        // 1. Export the managed .gitattributes block.
        let attr_path = self.path.join(".gitattributes");
        // Byte-oriented like every other .gitattributes touchpoint: the file
        // may legally hold non-UTF-8 pattern bytes (raw path bytes under
        // Unix), which a text read would reject.
        let content = match std::fs::read(&attr_path) {
            Ok(content) => content,
            // A missing .gitattributes is the common case: start from empty.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            // Any other read failure (permissions) must surface:
            // continuing with an empty base would clobber the user's file
            // with a block-only rewrite below.
            Err(e) => {
                return Err(Error::Other(format!(
                    "failed to read {}: {e}",
                    attr_path.display()
                )));
            },
        };
        let patterns = self.filter_patterns();
        let updated = gitattributes::with_managed_block(&content, &patterns);
        atomic_write(&attr_path, &updated)?;

        // 2. Configure the filter driver and the diff textconv.
        let f = format!("filter.{}", gitattributes::FILTER_NAME);
        self.set_raw_config(&format!("{f}.clean"), &format!("{quoted} clean %f"))?;
        self.set_raw_config(&format!("{f}.smudge"), &format!("{quoted} smudge %f"))?;
        // Long-running process filter: one daemon serves every blob of a git
        // operation, amortizing the per-file process cold start, repo open
        // and Argon2 (a shared batch salt). Clean/smudge above stay
        // configured: git >= 2.16 prefers `process`, older git ignores the
        // unknown key and falls back to them.
        self.set_raw_config(&format!("{f}.process"), &format!("{quoted} filter-process"))?;
        // Fail loudly (instead of committing plaintext) when the filter
        // cannot run, e.g. the binary was moved.
        self.set_raw_config(&format!("{f}.required"), "true")?;
        self.set_raw_config(
            &format!("diff.{}.textconv", gitattributes::FILTER_NAME),
            &format!("{quoted} diff"),
        )?;

        // 3. The legacy check hook is incompatible with filter mode. Look it up where install_hook
        //    would have put it (core.hooksPath-aware).
        let (hooks_dir, _) = self.hooks_dir()?;
        let hook = hooks_dir.join("pre-commit");
        if is_managed_hook(&hook)? {
            std::fs::remove_file(&hook)?;
            println!(
                "{} legacy pre-commit hook (incompatible with filter mode)",
                "Removed".yellow().bold()
            );
        } else if hook.exists() {
            warn!(
                "A foreign pre-commit hook exists at {}; it may block commits in filter mode.",
                hook.display()
            );
        }

        // 4. Decrypt the working tree where it is safe to do so.
        let (decrypted, needs_renormalize) = plan.as_ref().map_or((0, false), |plan| {
            (self.execute_migration(plan), plan.needs_renormalize)
        });

        println!(
            "{} git filter integration at {}",
            "Installed".green().bold(),
            self.path.display()
        );
        println!(
            "{}",
            "Working-tree files stay plaintext; git encrypts them on `git add` and decrypts on \
             checkout."
                .dimmed()
        );
        if !has_key {
            println!(
                "{}",
                "Run `git-se p` to set the password before staging files.".yellow()
            );
            return Ok(());
        }
        if decrypted > 0 {
            println!(
                "{} decrypted {decrypted} tracked file(s) in the working tree",
                "Auto".green().bold()
            );
        }
        if needs_renormalize {
            println!(
                "{}",
                "Some blobs need re-staging; run `git add --renormalize .` to encrypt them."
                    .yellow()
            );
        }
        Ok(())
    }

    /// Uninstall the git integration installed by `install` (either mode):
    /// remove the filter/textconv config, the managed `.gitattributes`
    /// block and the managed pre-commit hook, then restore the ciphertext
    /// working-tree copies of the tracked crypt files. Afterwards the
    /// repository behaves exactly as before the install: encryption and
    /// decryption are manual again (`git-se e` / `git-se d`).
    ///
    /// The crypt list, the password config and the salt cache are data, not
    /// integration — they are kept so manual operation (and a later
    /// reinstall) keeps working.
    pub fn uninstall(&self) -> Result<()> {
        let attr_path = self.path.join(".gitattributes");
        let attrs_installed = std::fs::read(&attr_path)
            .is_ok_and(|content| gitattributes::has_managed_block(&content));
        let (hooks_dir, _) = self.hooks_dir()?;
        let hook = hooks_dir.join("pre-commit");
        if !self.filter_installed() && !attrs_installed && !is_managed_hook(&hook)? {
            println!("No git-se integration found in {}.", self.path.display());
            return Ok(());
        }

        // The migration analysis MUST run while the filter config is still
        // in place: only then does `git diff HEAD` compare the worktree
        // through the clean filter and recognize the plaintext copy of a
        // ciphertext blob as clean, i.e. safe to re-checkout later. Dirty
        // files (staged or unstaged changes) keep their worktree copy — a
        // force-checkout would destroy uncommitted work.
        let migration = self.clean_crypt_paths();

        // 1. Unset the filter driver and textconv config written by install; missing keys are
        //    tolerated (partial installs).
        let f = format!("filter.{}", gitattributes::FILTER_NAME);
        for key in [
            format!("{f}.clean"),
            format!("{f}.smudge"),
            format!("{f}.process"),
            format!("{f}.required"),
            format!("diff.{}.textconv", gitattributes::FILTER_NAME),
        ] {
            self.unset_raw_config(&key)?;
        }

        // 2. Strip the managed .gitattributes block; delete the file when the block was its only
        //    content.
        match std::fs::read(&attr_path) {
            Ok(content) => {
                let rest = gitattributes::without_managed_block(&content);
                if is_blank(&rest) {
                    std::fs::remove_file(&attr_path)?;
                } else {
                    atomic_write(&attr_path, &rest)?;
                }
            },
            // A missing file means there is no block to strip (partial
            // installs are tolerated, like the config unsets above).
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
            Err(e) => return Err(e.into()),
        }

        // 3. Remove the managed pre-commit hook (hook-mode artifact); foreign hooks are never
        //    touched.
        if is_managed_hook(&hook)? {
            std::fs::remove_file(&hook)?;
            println!("{} pre-commit hook", "Removed".green().bold());
        } else if hook.exists() {
            warn!(
                "A foreign pre-commit hook exists at {}; left untouched.",
                hook.display()
            );
        }

        // 4. Restore the ciphertext worktree copies. With the filters and attributes gone, `git
        //    checkout --force HEAD` writes the raw ciphertext blobs back to the worktree.
        let mut restored = 0;
        match migration {
            Ok((to_restore, dirty)) => {
                restored = self.force_recheckout(&to_restore, "uninstall");
                if !dirty.is_empty() {
                    println!(
                        "{}",
                        format!(
                            "{} crypt-list file(s) with uncommitted changes stay plaintext; run \
                             `git-se e` to encrypt them before committing.",
                            dirty.len()
                        )
                        .yellow()
                    );
                }
            },
            Err(e) => warn!(
                "could not analyze the working tree ({e}); it was left untouched. Restore the \
                 ciphertext copies manually with `git checkout -- <paths>`."
            ),
        }

        println!(
            "{} git integration at {}",
            "Uninstalled".green().bold(),
            self.path.display()
        );
        if restored > 0 {
            println!(
                "{}",
                format!("Restored {restored} ciphertext working-tree file(s).").dimmed()
            );
        }
        Ok(())
    }
}

/// Whether leftover `.gitattributes` content is blank (whitespace only):
/// uninstall's signal that the managed block was the file's only content and
/// the file itself can go.
///
/// Non-UTF-8 bytes always count as content — matching the byte-oriented
/// handling everywhere else — while for valid UTF-8 this is exactly
/// `str::trim().is_empty()`, preserving the pre-existing behavior.
fn is_blank(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|s| s.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use path_absolutize::Absolutize;

    use super::*;
    use crate::repo::init_temp_repo;

    /// A `.gitattributes` holding non-UTF-8 pattern bytes (legal content
    /// under Unix) must work with install/refresh/uninstall exactly like a
    /// UTF-8 one.
    ///
    /// The managed block is added, updated and stripped, and the raw user
    /// line survives every step (it also keeps the file from being deleted
    /// as "blank" at uninstall time).
    #[test]
    fn test_gitattributes_non_utf8_install_refresh_uninstall() -> Result<()> {
        let dir = init_temp_repo();
        let repo_path = dir.path().absolutize().unwrap().to_path_buf();
        let mut repo = Repo::open(&repo_path)?;
        repo.set_config("key", "test-key")?;
        std::fs::write(repo_path.join("a.txt"), b"x")?;
        repo.conf.add_one_path_to_crypt_list("a.txt")?;

        let mut original = b"*.bin text\n".to_vec();
        original.extend_from_slice(&[0xff, 0xfe, b' ', b'r', b'a', b'w', b'\n']);
        let attr_path = repo_path.join(".gitattributes");
        std::fs::write(&attr_path, &original)?;

        // install: appends the managed block, keeps the raw line verbatim
        repo.install_filter()?;
        let installed = std::fs::read(&attr_path)?;
        assert!(gitattributes::has_managed_block(&installed));
        assert!(installed.starts_with(&original));
        assert!(String::from_utf8_lossy(&installed).contains("a.txt filter=git-se diff=git-se"));

        // refresh: a crypt-list change rewrites the block in place
        std::fs::write(repo_path.join("b.txt"), b"y")?;
        repo.conf.add_one_path_to_crypt_list("b.txt")?;
        repo.refresh_gitattributes()?;
        let refreshed = std::fs::read(&attr_path)?;
        assert!(refreshed.starts_with(&original));
        assert!(String::from_utf8_lossy(&refreshed).contains("b.txt filter=git-se diff=git-se"));

        // uninstall: strips the block; the non-UTF-8 line keeps the file
        repo.uninstall()?;
        assert_eq!(std::fs::read(&attr_path)?, original);
        Ok(())
    }
}
