use std::path::{Path, PathBuf};

use assert2::assert;
use colored::Colorize;
use config_file2::Storable;
use fuck_backslash::FuckBackslash;
use log::{debug, info};
use path_absolutize::Absolutize as _;
use pathdiff::diff_paths;
use serde::{Deserialize, Serialize};

pub const CONFIG_FILE_NAME: &str = concat!(env!("CARGO_CRATE_NAME"), ".toml");

#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// **absolute path** of the repo. This config item will not be ser/de from
    /// file; instead, it will be set by cli param.
    #[serde(skip)]
    pub repo_path: PathBuf,
    /// config file path
    #[serde(skip)]
    pub(crate) config_path: PathBuf,
    /// whether to use zstd
    pub use_zstd: bool,
    /// zstd compression level (1-22).
    pub zstd_level: u8,
    /// list of files (patterns) to encrypt
    pub crypt_list: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            repo_path: PathBuf::from("."),
            config_path: PathBuf::from(CONFIG_FILE_NAME),
            use_zstd: true,
            zstd_level: 15,
            crypt_list: vec![],
        }
    }
}

impl Storable for Config {
    fn path(&self) -> impl AsRef<Path> {
        &self.config_path
    }
}

impl Config {
    /// The path must be absolute.
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self::default().with_repo_path(path)
    }
    /// The path must be absolute.
    pub fn with_repo_path(mut self, path: impl AsRef<Path>) -> Self {
        let path = path.as_ref();
        self.repo_path = path.to_path_buf();
        self.config_path = path.join(CONFIG_FILE_NAME);
        self
    }

    /// Add one path to crypt list
    ///
    /// path could be either relative or absolute.
    pub fn add_one_path_to_crypt_list(&mut self, path: impl AsRef<Path>) {
        let path = path
            .as_ref()
            .absolutize_from(&self.repo_path)
            .expect("path absolutize failed");
        debug!("adding path to crypt list: {}", path.display());
        assert!(path.exists(), "file or dir not exist: {:?}", path);
        let path_relative_to_repo = diff_paths(path.as_ref(), &self.repo_path)
            .unwrap_or_else(|| path.to_path_buf())
            .fuck_backslash();
        debug!(
            "path diff: {} to {}",
            path.display(),
            self.repo_path.display()
        );
        assert!(
            !path_relative_to_repo.is_absolute(),
            "get absolute path `{}`, please use relative path instead",
            path_relative_to_repo.display()
        );
        info!(
            "Add to encrypt list: {}",
            format!("{}", path_relative_to_repo.display()).green()
        );
        self.crypt_list
            .push(path_relative_to_repo.to_string_lossy().into_owned());
    }

    /// Add the given paths to the encrypt list. This function will be called
    /// seldomly, so it's not a performance issue.
    pub fn add_paths_to_crypt_list(&mut self, paths: &[impl AsRef<Path>]) -> anyhow::Result<()> {
        for x in paths {
            self.add_one_path_to_crypt_list(x.as_ref());
        }
        debug!("store config to {}", self.config_path.display());
        self.store().map_err(|e| anyhow::anyhow!(e))
    }
}

#[cfg(test)]
mod tests {
    use std::{assert, fs};

    use anyhow::Ok;
    use config_file2::LoadConfigFile;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_add_one_file_to_crypt_list() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?.keep();
        let file_path = temp_dir.join("test.toml");
        let mut config = Config::load_or_default(file_path)?.with_repo_path(&*temp_dir);

        let path_to_add = temp_dir.join("testdir");
        fs::create_dir(&path_to_add)?;
        config.add_one_path_to_crypt_list(path_to_add.as_os_str().to_string_lossy().as_ref());
        println!("{:?}", config.crypt_list.first().unwrap());
        assert!(
            config
                .repo_path
                .join(config.crypt_list.first().unwrap())
                .is_dir(),
            "needs to be dir: {}",
            config.crypt_list.first().unwrap()
        );
        Ok(())
    }
}
