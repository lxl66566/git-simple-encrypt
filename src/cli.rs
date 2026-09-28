use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use config_file2::Storable;
use log::{debug, info, warn};

use crate::{
    error::{Error, Result},
    repo::Repo,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, after_help = r#"Examples:
git-se p                    # Set/update master password
git-se add file.txt  mydir  # Add files/folders to the encryption list
git-se e                    # Encrypt all files in the list
git-se d                    # Decrypt all files in the list
git-se e xxx.txt dir1 ...   # Encrypt specific files
git-se d xxx.txt dir1 ...   # Decrypt specific files
git-se i                    # Install git filter integration: automatic encryption / decryption
"#)]
#[clap(args_conflicts_with_subcommands = true)]
pub struct Cli {
    /// Encrypt, Decrypt and Add
    #[command(subcommand)]
    pub command: SubCommand,
    /// Repository path, allow both relative and absolute path.
    #[arg(short, long, global = true)]
    #[clap(value_parser = repo_path_parser, default_value = ".")]
    pub repo: PathBuf,
}

fn repo_path_parser(path: &str) -> Result<PathBuf, String> {
    match path_absolutize::Absolutize::absolutize(Path::new(path)) {
        Ok(p) => Ok(p.into_owned()),
        Err(e) => Err(e.to_string()),
    }
}

#[derive(Subcommand, Debug)]
pub enum SubCommand {
    /// Encrypt all files with crypt attr.
    #[clap(alias("e"))]
    Encrypt {
        /// The files or folders to be encrypted.
        paths: Vec<PathBuf>,
    },
    /// Decrypt all files with crypt attr and `.enc` extension.
    #[clap(alias("d"))]
    Decrypt {
        /// The files or folders to be decrypted.
        paths: Vec<PathBuf>,
    },
    /// Mark files or folders as need-to-be-crypted.
    Add { paths: Vec<PathBuf> },
    /// Set key or other config items.
    Set {
        #[clap(subcommand)]
        field: SetField,
    },
    /// Set password interactively.
    #[clap(alias("p"))]
    Pwd,
    /// Check if all files in the crypt list are encrypted.
    #[clap(alias("c"))]
    Check {
        /// The files or folders to check. If empty, checks all files in the
        /// crypt list.
        paths: Vec<PathBuf>,
        /// Only check files staged for commit (used by pre-commit hook).
        #[arg(long, default_value_t = false)]
        staged: bool,
    },
    /// Install git integration.
    ///
    /// Filter mode (default, transcrypt-style) exports `.gitattributes` and
    /// configures git clean/smudge filters plus a diff textconv: files in the
    /// crypt list stay plaintext in the working tree, git encrypts them on
    /// `git add` and decrypts on checkout, and `git diff` shows plaintext.
    /// Hook mode keeps the legacy behavior: only a pre-commit check hook,
    /// with manual `e`/`d`.
    #[clap(alias("i"))]
    Install {
        /// What to install.
        #[arg(long, value_enum, default_value_t = InstallMode::Filter)]
        mode: InstallMode,
    },
    /// Git clean filter: encrypt stdin to stdout. Invoked by git through
    /// `filter.git-se.clean` with the filtered path (git's %f placeholder).
    Clean {
        /// Path of the filtered file, relative to the repo root.
        path: PathBuf,
    },
    /// Git smudge filter: decrypt stdin to stdout. Invoked by git through
    /// `filter.git-se.smudge` with the filtered path (git's %f placeholder).
    Smudge {
        /// Path of the filtered file, relative to the repo root.
        path: PathBuf,
    },
    /// Decrypt ciphertext to stdout for `git diff` (configured as
    /// `diff.git-se.textconv`). Reads the given file, or stdin when omitted.
    Diff {
        /// File holding the ciphertext (git passes a blob temp file here).
        file: Option<PathBuf>,
    },
}

/// What `git-se install` sets up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum InstallMode {
    /// Export `.gitattributes` and configure clean/smudge filters and the
    /// plaintext diff; encryption becomes fully automatic.
    Filter,
    /// Only install the legacy pre-commit check hook; encrypt/decrypt stays
    /// manual (`git-se e` / `git-se d`).
    Hook,
}

impl SubCommand {
    /// Whether this command is a git filter/textconv callback. Git invokes
    /// these once per file with data on stdin/stdout, so they must stay quiet
    /// and fast.
    #[must_use]
    pub const fn is_filter_driver(&self) -> bool {
        matches!(
            self,
            Self::Clean { .. } | Self::Smudge { .. } | Self::Diff { .. }
        )
    }
}

#[derive(Debug, Subcommand)]
pub enum SetField {
    /// Set key
    Key { value: String },
    /// Set zstd compression level
    ZstdLevel {
        #[clap(value_parser = validate_zstd_level)]
        value: u8,
    },
    /// Set zstd compression enable or not
    EnableZstd {
        #[clap(value_parser = validate_bool)]
        value: bool,
    },
}

impl SetField {
    /// Apply the field update to the given repo's config.
    ///
    /// `Key` only touches the git config (no toml write); the other fields
    /// mutate the in-memory conf and persist it to the config file.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying git command or the config file write
    /// fails.
    pub fn set(&self, repo: &mut Repo) -> Result<()> {
        match self {
            Self::Key { value } => {
                warn!("`set key` is deprecated, please use `pwd` or `p` instead.");
                repo.set_config("key", value)?;
                info!("Master key updated.");
                // The key lives in git config, not in the toml; nothing to
                // persist in the config file.
                Ok(())
            },
            Self::EnableZstd { value } => {
                repo.conf.use_zstd = *value;
                info!("zstd compression enabled: {value}");
                save_conf(repo)
            },
            Self::ZstdLevel { value } => {
                repo.conf.zstd_level = *value;
                info!("zstd compression level set to {value}");
                save_conf(repo)
            },
        }
    }
}

/// Persist the config toml after an in-memory mutation.
fn save_conf(repo: &Repo) -> Result<()> {
    debug!("store config to {}", repo.conf.config_path.display());
    repo.conf.save().map_err(|e| Error::Config(e.to_string()))
}

fn validate_zstd_level(value: &str) -> Result<u8, String> {
    let value = value
        .parse::<u8>()
        .map_err(|_| "value should be a number")?;
    if (1..=22_u8).contains(&value) {
        Ok(value)
    } else {
        Err("value should be 1-22".to_string())
    }
}

fn validate_bool(value: &str) -> Result<bool, String> {
    match value {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err("value should be `true`, `false`, `1` or `0`".into()),
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    #[test]
    fn repo_path_parser_resolves_relative() {
        // "." should absolutize to the current working directory.
        let parsed = repo_path_parser(".").unwrap();
        assert!(parsed.is_absolute());
    }
}
