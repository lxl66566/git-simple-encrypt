use std::{path::PathBuf, sync::LazyLock as Lazy};

use clap::{Parser, Subcommand};

use crate::git_command::config::ConfigField;

#[cfg(not(test))]
pub static CLI: Lazy<Cli> = Lazy::new(Cli::parse);
#[cfg(test)]
pub static CLI: Lazy<Cli> = Lazy::new(Cli::default);

#[derive(Parser, Clone, Debug)]
#[command(author, version, about, long_about = None, after_help = r#"Examples:
git-se set-key 123456   # set password as `123456`
git-se add file.txt     # mark `file.txt` as need-to-be-crypted
git-se e                # encrypt current repo with all marked files
git-se d                # decrypt current repo
"#)]
#[clap(args_conflicts_with_subcommands = true)]
pub struct Cli {
    /// Encrypt, Decrypt and Add
    #[command(subcommand)]
    pub command: SubCommand,
    /// Repository path
    #[arg(short, long, global = true)]
    #[clap(default_value = ".")]
    pub repo: PathBuf,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            command: SubCommand::default(),
            repo: PathBuf::from("."),
        }
    }
}

#[derive(Subcommand, Debug, Clone, Default)]
pub enum SubCommand {
    /// Encrypt all files with crypt attr.
    #[default]
    #[clap(alias("e"))]
    Encrypt,
    /// Decrypt all files with crypt attr and `.enc` extension.
    #[clap(alias("d"))]
    Decrypt,
    /// Mark file or folder as need-to-be-crypted.
    Add { path: PathBuf },
    /// Cancel mark of file or folder.
    Remove { path: PathBuf },
    /// Set password (KEY) for encrypting.
    SetKey { key: String },
    /// Set other config items.
    Set { field: ConfigField, value: String },
}
