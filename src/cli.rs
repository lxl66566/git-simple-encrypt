use std::{path::PathBuf, sync::LazyLock as Lazy};

use assert2::assert;
use clap::{Parser, Subcommand};

use crate::{
    config::Config,
    repo::{GitCommand, Repo},
};

#[derive(Parser, Clone, Debug)]
#[command(author, version, about, long_about = None, after_help = r#"Examples:
git-se set key 123456   # set password as `123456`
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
    /// Mark files or folders as need-to-be-crypted.
    Add { path: Vec<PathBuf> },
    /// Set key or other config items.
    Set { field: SetField, value: String },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, enum_tools::EnumTools)]
#[enum_tools(as_str, from_str)]
#[repr(i8)]
#[allow(non_camel_case_types)]
pub enum SetField {
    key,
    enable_zstd,
    zstd_level,
}

impl SetField {
    pub fn set(&self, repo: &mut Repo, value: &str) -> anyhow::Result<()> {
        // check input
        match self {
            Self::key => repo.set_config(self.as_str(), value)?,
            Self::enable_zstd => {
                assert!(
                    ["true", "false", "1", "0"].contains(&value),
                    "value should be `true`, `false`, `1` or `0`"
                );
                repo.conf.use_zstd = value == "true" || value == "1";
            }
            Self::zstd_level => {
                let temp = value.parse::<u8>();
                assert!(temp.is_ok(), "value should be a number");
                let temp = temp.unwrap();
                assert!(temp >= 1 && temp <= 22, "value should be 1-22");
                repo.conf.zstd_level = temp;
            }
        };
        Ok(())
    }
}
