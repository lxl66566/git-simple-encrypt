use std::path::{Path, PathBuf};

use assert2::assert;
use colored::Colorize;
use config_file2::StoreConfigFile;
use log::{debug, info, warn};
use path_absolutize::Absolutize as _;
use pathdiff::diff_paths;
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::{
    crypt::{COMPRESSED_EXTENSION, ENCRYPTED_EXTENSION},
    utils::Git2Patch,
};

pub const CONFIG_FILE_NAME: &str = concat!(env!("CARGO_CRATE_NAME"), ".toml");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// **absolute path** of the repo. This config item will not be ser/de from
    /// file; instead, it will be set by cli param.
    #[serde(skip)]
    pub repo_path: PathBuf,
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
            use_zstd: true,
            zstd_level: 15,
            crypt_list: vec![],
        }
    }
}

impl Config {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self::default().with_repo_path(path)
    }
    pub fn with_repo_path(mut self, path: impl AsRef<Path>) -> Self {
        self.repo_path = path
            .as_ref()
            .absolutize()
            .expect("path absolutize failed")
            .to_path_buf();
        self
    }
    /// The absolute path of the config file.
    pub fn config_path(&self) -> PathBuf {
        self.repo_path.join(CONFIG_FILE_NAME)
    }
    /// Add one path to crypt list
    ///
    /// path: relative path to a file or dir.
    pub fn add_one_file_to_crypt_list(&mut self, path: impl AsRef<Path>) {
        // path is the relative path to the current dir (or absolute path)
        let path = path.as_ref().absolutize().expect("path absolutize failed");

        debug!("add_one_file_to_crypt_list: {}", path.display());
        assert!(
            ![ENCRYPTED_EXTENSION, COMPRESSED_EXTENSION].contains(
                &path
                    .extension()
                    .unwrap_or_default()
                    .to_str()
                    .unwrap_or_default()
            ),
            "Cannot add file with extension `{}`, `{}`",
            ENCRYPTED_EXTENSION,
            COMPRESSED_EXTENSION
        );
        assert!(path.exists(), "file not exist: {:?}", path);

        // path is the relative path to the repo
        let path_relative_to_repo = diff_paths(path.as_ref(), &self.repo_path)
            .unwrap_or_else(|| path.to_path_buf())
            .patch();
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
        // there's no need to use ``, the output path has ""
        info!(
            "Add to crypt list: {}",
            format!("{}", path_relative_to_repo.display()).green()
        );
        self.crypt_list
            .push(path_relative_to_repo.to_string_lossy().replace('\\', "/"));

        // check extension
        if path.is_dir() {
            for entry in WalkDir::new(path)
                .into_iter()
                .filter_map(std::result::Result::ok)
            {
                if let Some(ext) = entry.path().extension().and_then(|ext| ext.to_str())
                    && [COMPRESSED_EXTENSION, ENCRYPTED_EXTENSION].contains(&ext)
                {
                    warn!(
                        "{}",
                        format!(
                            "adding dir that contains file with no-good extension: {}",
                            entry.path().display()
                        )
                        .yellow()
                    );
                }
            }
        }
    }

    pub fn add_to_crypt_list(&mut self, paths: &[impl AsRef<Path>]) -> anyhow::Result<()> {
        paths
            .iter()
            .for_each(|x| self.add_one_file_to_crypt_list(x.as_ref()));
        self.store(CONFIG_FILE_NAME).map_err(|e| anyhow::anyhow!(e))
    }
}

#[cfg(test)]
mod tests {
    use std::{assert, fs};

    use anyhow::Ok;
    use config_file2::LoadConfigFile;
    use log::LevelFilter;
    use tempfile::TempDir;

    use super::*;

    #[inline]
    pub fn log_init() {
        #[cfg(not(debug_assertions))]
        log_init_with_default_level(LevelFilter::Info);
        #[cfg(debug_assertions)]
        log_init_with_default_level(LevelFilter::Debug);
    }

    #[inline]
    pub fn log_init_with_default_level(level: LevelFilter) {
        _ = pretty_env_logger::formatted_builder()
            .filter_level(level)
            .format_timestamp_millis()
            .filter_module("j4rs", LevelFilter::Info)
            .parse_default_env()
            .try_init();
    }

    #[test]
    fn test_add_one_file_to_crypt_list() -> anyhow::Result<()> {
        log_init();
        let temp_dir = TempDir::new()?.into_path();
        let file_path = temp_dir.join("test.toml");
        let mut config = Config::load_or_default(file_path)?.with_repo_path(&*temp_dir);

        let path_to_add = temp_dir.join("testdir");
        fs::create_dir(&path_to_add)?;
        config.add_one_file_to_crypt_list(path_to_add.as_os_str().to_string_lossy().as_ref());
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

    #[test]
    #[should_panic]
    fn test_add_enc_file() {
        log_init();
        let temp_dir = TempDir::new().unwrap().into_path();
        std::fs::File::create(temp_dir.join("test.enc")).unwrap();
        let file_path = temp_dir.join("test");
        let mut config = Config::new(file_path);
        config.add_one_file_to_crypt_list("test.enc");
    }

    #[test]
    #[should_panic]
    fn test_add_config_file() {
        log_init();
        let temp_dir = TempDir::new().unwrap().into_path();
        let file_path = temp_dir.join("config.toml");
        let mut config = Config::load_or_default(file_path).unwrap();
        config.add_one_file_to_crypt_list("config.toml");
    }
}
