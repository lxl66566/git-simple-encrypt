//! The repository handle ([`Repo`]) and its git-se commands.
//!
//! Submodules split the supporting layers:
//! - [`git`]: git subprocess plumbing (the cat-file batch session, `-z` parsers, HEAD tree / index
//!   enumeration)
//! - [`config_file`]: repo-local config reads/writes, incl. the direct config-file surgery that
//!   keeps secret values out of argv
//! - [`hooks`]: the pre-commit hook template and its installation
//! - [`check`]: the `check` command family (worktree and staged-blob verification)
//! - [`migration`]: install/uninstall-time working-tree migration analysis
//! - [`install`]: the filter-integration install/uninstall sequences

mod check;
mod config_file;
mod git;
mod hooks;
mod install;
mod migration;

use std::path::{Path, PathBuf};

use config_file2::LoadConfigFile;
use log::{info, warn};
use zeroize::Zeroizing;

use crate::{
    config::{CONFIG_FILE_NAME, Config},
    crypt::{HEADER_LEN, has_gitse_magic},
    error::{Error, Result},
    gitattributes,
    utils::{atomic_write, prompt_password},
};

pub const GIT_CONFIG_PREFIX: &str =
    const_str::replace!(concat!(env!("CARGO_CRATE_NAME"), "."), "_", "-");

#[derive(Debug, Clone)]
pub struct Repo {
    /// The absolute worktree root this repo was opened from.
    ///
    /// Public for v3 source compatibility, but treat it as read-only: it
    /// must stay the absolute worktree root that [`Repo::open`] /
    /// [`Repo::discover`] validated, and mutating it bypasses that
    /// validation. There is intentionally no `Default` — a defaulted
    /// instance is an invalid one.
    pub path: PathBuf,
    pub conf: Config,
}

impl Repo {
    /// Open a repo. The `path` argument must be an absolute path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        debug_assert!(path.as_ref().is_absolute(), "given path must be absolute");
        let mut repo_path = path.as_ref().to_path_buf();
        if !repo_path.exists() {
            return Err(Error::RepoNotFound(repo_path));
        }
        if !repo_path.is_dir() {
            return Err(Error::NotADirectory(repo_path));
        }
        if repo_path
            .file_name()
            .ok_or_else(|| Error::Other("Filename not found".to_string()))?
            == ".git"
        {
            repo_path.pop();
        }
        // A usable work tree must contain a `.git` entry: either a directory
        // (normal clone) or a `gitdir: <path>` pointer file (linked worktree /
        // submodule). Rejecting other directories up front avoids obscure git
        // errors from `get_key()`. The salt cache resolves such pointer files
        // to the real gitdir on its own (see `salt_cache::resolve_git_dir`),
        // so cache writes keep working from linked worktrees too.
        // No dedicated Error variant for v3 compatibility (the enum is not
        // `#[non_exhaustive]`); the message rides in `Error::Other`.
        let dot_git = repo_path.join(".git");
        if !dot_git.is_dir() && !dot_git.is_file() {
            return Err(Error::Other(format!(
                "not a git repository: {}",
                repo_path.display()
            )));
        }
        info!("Open repo: {}", repo_path.display());
        let config_file_path = repo_path.join(CONFIG_FILE_NAME);
        if !config_file_path.exists() {
            warn!(
                "Config file not found: `{}`, using default config instead...",
                config_file_path.display()
            );
        }
        // A GITSE-encrypted config (e.g. left behind by an `e .` from an
        // older release that did not exclude it) would hard-fail every
        // command — including the decrypt that could recover it. Fall back
        // to the default config instead so `git-se d` remains usable.
        let config_is_own_ciphertext = std::fs::read(&config_file_path).is_ok_and(|bytes| {
            bytes
                .first_chunk::<HEADER_LEN>()
                .is_some_and(has_gitse_magic)
        });
        let conf = if config_is_own_ciphertext {
            warn!(
                "Config file `{}` is encrypted (likely by an `e .` run); using the default config \
                 so the file can be decrypted back. Your settings return once it is restored.",
                config_file_path.display()
            );
            Config::default()
        } else {
            Config::load_or_default(&config_file_path).map_err(|e| Error::Config(e.to_string()))?
        }
        .with_repo_path(&repo_path);
        Ok(Self {
            path: repo_path,
            conf,
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn to_absolute_path(&self, path: impl AsRef<Path>) -> PathBuf {
        self.path.join(path.as_ref())
    }

    /// Read the master key from git config.
    ///
    /// Returns an error if the key has not been configured. The returned
    /// string is zeroized on drop.
    pub fn get_key(&self) -> Result<Zeroizing<String>> {
        self.get_config("key").map(Zeroizing::new).map_err(|e| {
            Error::Other(format!(
                "Key not found, please run `git-se p` (or `git-se set key <VALUE>`) first: {e}"
            ))
        })
    }

    /// Set the key interactively by prompting on stdin.
    pub fn set_key_interactive(&self) -> Result<()> {
        let key = prompt_password("Please input your key: ")?;
        self.set_config("key", key.as_str())?;
        info!("Master key updated.");
        Ok(())
    }

    /// Like [`Repo::open`], but walk up from `start` until a directory with a
    /// `.git` entry is found.
    ///
    /// Git runs the clean/smudge filter processes from the worktree root,
    /// but manual invocations from subdirectories should work too. This is
    /// a strict superset of `Repo::open` at the repo root, and every CLI
    /// command resolves its repo through here.
    pub fn discover(start: impl AsRef<Path>) -> Result<Self> {
        debug_assert!(start.as_ref().is_absolute(), "given path must be absolute");
        let mut dir = start.as_ref().to_path_buf();
        loop {
            let dot_git = dir.join(".git");
            if dot_git.is_dir() || dot_git.is_file() {
                return Self::open(&dir);
            }
            if !dir.pop() {
                return Err(Error::Other(format!(
                    "not a git repository: {}",
                    start.as_ref().display()
                )));
            }
        }
    }

    /// Whether the filter integration is installed in this repo: the
    /// clean/smudge drivers and/or the process filter.
    #[must_use]
    pub fn filter_installed(&self) -> bool {
        // `required` is written by every install of the filter mode; the
        // `process` check keeps this true for setups wired to the process
        // filter alone.
        self.get_raw_config(&format!("filter.{}.required", gitattributes::FILTER_NAME))
            .is_ok()
            || self
                .get_raw_config(&format!("filter.{}.process", gitattributes::FILTER_NAME))
                .is_ok()
    }

    /// Refresh the managed `.gitattributes` block after crypt-list changes.
    ///
    /// No-op unless the block already exists (i.e. filter mode is active);
    /// the hook-only workflow never touches `.gitattributes`. Reading is
    /// byte-oriented like the other touchpoints, so non-UTF-8 pattern lines
    /// are preserved instead of aborting the refresh.
    pub fn refresh_gitattributes(&self) -> Result<()> {
        let attr_path = self.path.join(".gitattributes");
        let content = match std::fs::read(&attr_path) {
            Ok(content) => content,
            // A missing .gitattributes means filter mode is not active here.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        if !gitattributes::has_managed_block(&content) {
            return Ok(());
        }
        let updated = gitattributes::with_managed_block_bytes(&content, &self.filter_patterns());
        if updated != content {
            atomic_write(&attr_path, &updated)?;
        }
        Ok(())
    }

    /// Final gitignore-style patterns for the crypt list: directory entries
    /// get a `/**` suffix (a bare directory pattern does not cascade to its
    /// contents in `.gitattributes`).
    fn filter_patterns(&self) -> Vec<String> {
        self.conf
            .crypt_list
            .iter()
            .map(|entry| {
                // The `/**` suffix is a real glob and must stay inside the
                // quotes when the path itself needs quoting, so it is passed
                // as a suffix rather than appended to the escaped pattern.
                if self.path.join(entry).is_dir() {
                    gitattributes::escape_pattern(entry, "/**")
                } else {
                    gitattributes::escape_pattern(entry, "")
                }
            })
            .collect()
    }
}

/// Create a temp directory holding a freshly `git init`-ed repository, for
/// tests across this module tree.
#[cfg(test)]
fn init_temp_repo() -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().unwrap();
    // `git init` so that .git/ exists for hook installation & config.
    std::process::Command::new("git")
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    dir
}

#[cfg(test)]
mod tests {
    use path_absolutize::Absolutize;

    use super::*;
    use crate::crypt::HEADER_LEN;

    #[test]
    fn test_repo_open() -> Result<()> {
        let repo = Repo::open(Path::new(".").absolutize()?)?;
        assert_eq!(repo.path().file_name().unwrap(), "git-simple-encrypt");
        let repo = Repo::open(Path::new("./.git").absolutize()?)?;
        assert_eq!(repo.path().file_name().unwrap(), "git-simple-encrypt");
        Ok(())
    }

    #[test]
    fn test_repo_open_rejects_non_git_directory() {
        let dir = tempfile::TempDir::new().unwrap();
        let repo_path = dir.path().absolutize().unwrap().to_path_buf();

        let err = Repo::open(&repo_path).unwrap_err().to_string();
        assert!(err.contains("not a git repository"), "got: {err}");
    }

    #[test]
    fn test_repo_open_accepts_worktree_gitdir_pointer() -> Result<()> {
        // A linked worktree's `.git` is a file pointing at the main gitdir;
        // only its form (file vs directory) is checked here, validating the
        // target is git's own job.
        let dir = tempfile::TempDir::new().unwrap();
        let repo_path = dir.path().absolutize().unwrap().to_path_buf();
        std::fs::write(
            repo_path.join(".git"),
            format!(
                "gitdir: {}\n",
                repo_path.join("main").join(".git").display()
            ),
        )?;

        let repo = Repo::open(&repo_path)?;
        assert_eq!(repo.path(), repo_path.as_path());
        Ok(())
    }

    #[test]
    fn test_repo_open_recovers_from_encrypted_config() -> Result<()> {
        // A config encrypted by an older release's `e .` must not lock out
        // every command: open falls back to the default config so the file
        // can be decrypted back.
        let dir = init_temp_repo();
        let repo_path = dir.path().absolutize().unwrap().to_path_buf();
        let mut encrypted_config = b"GITSE".to_vec();
        encrypted_config.resize(HEADER_LEN, 0);
        encrypted_config.extend_from_slice(b"ciphertext bytes");
        std::fs::write(repo_path.join(CONFIG_FILE_NAME), encrypted_config)?;

        let repo = Repo::open(&repo_path)?;
        assert_eq!(repo.conf, Config::default().with_repo_path(&repo_path));
        Ok(())
    }
}
