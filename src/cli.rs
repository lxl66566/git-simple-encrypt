use std::path::PathBuf;

use assert2::assert;
use clap::{Parser, Subcommand};
use config_file2::StoreConfigFile;
use log::warn;

use crate::{
    config::CONFIG_FILE_NAME,
    repo::{GitCommand, Repo},
};

#[derive(Parser, Clone, Debug)]
#[command(author, version, about, long_about = None, after_help = r#"Examples:
git-se p                # set password
git-se add file.txt     # mark `file.txt` as need-to-be-crypted
git-se e                # encrypt current repo with all marked files
git-se d                # decrypt current repo
git-se d 'src/*'        # decrypt all encrypted files in `src` folder
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
    Decrypt {
        /// The files or folders to be decrypted, use wildcard matches.
        path: Option<String>,
    },
    /// Mark files or folders as need-to-be-crypted.
    Add {
        #[clap(required = true)]
        paths: Vec<String>,
    },
    /// Set key or other config items.
    Set { field: SetField, value: String },
    /// Set password interactively.
    #[clap(alias("p"))]
    Pwd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, enum_tools::EnumTools)]
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
        match self {
            Self::key => {
                warn!("`set key` is deprecated, please use `pwd` or `p` instead.");
                repo.set_config(self.as_str(), value)?;
            }
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
                assert!((1..=22).contains(&temp), "value should be 1-22");
                repo.conf.zstd_level = temp;
            }
        };
        println!("`{}` set to `{}`", self.as_str(), value);
        if self != &Self::key {
            repo.conf.store(CONFIG_FILE_NAME)?;
        }
        Ok(())
    }
}
