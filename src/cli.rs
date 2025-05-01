use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use config_file2::StoreConfigFile;
use log::{info, warn};

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
    /// Repository path, allow both relative and absolute path.
    #[arg(short, long, global = true)]
    #[clap(value_parser = repo_path_parser, default_value = ".")]
    pub repo: PathBuf,
}

fn repo_path_parser(path: &str) -> Result<PathBuf, String> {
    match path_absolutize::Absolutize::absolutize(Path::new(path)) {
        Ok(p) => Ok(p.into_owned()),
        Err(e) => Err(format!("{e}")),
    }
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
    Set {
        #[clap(subcommand)]
        field: SetField,
    },
    /// Set password interactively.
    #[clap(alias("p"))]
    Pwd,
}

#[derive(Debug, Subcommand, Clone)]
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
    /// Set a field.
    ///
    /// # Errors
    ///
    /// Returns an error if fail to exec git command or fail to write to config
    /// file.
    pub fn set(&self, repo: &mut Repo) -> anyhow::Result<()> {
        match self {
            Self::Key { value } => {
                warn!("`set key` is deprecated, please use `pwd` or `p` instead.");
                repo.set_config("key", value)?;
                info!("key set to `{value}`");
            }
            Self::EnableZstd { value } => {
                repo.conf.use_zstd = *value;
                info!("zstd compression enabled: {value}");
            }
            Self::ZstdLevel { value } => {
                repo.conf.zstd_level = *value;
                info!("zstd compression level set to {value}");
            }
        }
        repo.conf.store(CONFIG_FILE_NAME)?;

        Ok(())
    }
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
