use std::path::{Path, PathBuf};

use config_file2::Storable;
use fuck_backslash::FuckBackslash;
use log::{debug, info};
use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    utils::{PathRelativeTo, has_git_component, path_relative_to, style::Colorize},
};

pub const CONFIG_FILE_NAME: &str = concat!(env!("CARGO_CRATE_NAME"), ".toml");

/// Default of [`Config::use_zstd`]; shared by [`Config::default`] and the
/// serde default so the two can never drift apart.
const DEFAULT_USE_ZSTD: bool = true;
/// Default of [`Config::zstd_level`]; shared by [`Config::default`] and the
/// serde default so the two can never drift apart.
const DEFAULT_ZSTD_LEVEL: u8 = 3;
/// Valid zstd compression level range (inclusive); mirrors the CLI parser.
const ZSTD_LEVEL_RANGE: std::ops::RangeInclusive<u8> = 1..=22;

const fn default_use_zstd() -> bool {
    DEFAULT_USE_ZSTD
}

const fn default_zstd_level() -> u8 {
    DEFAULT_ZSTD_LEVEL
}

/// Reject out-of-range levels at deserialization time.
///
/// The CLI validates its own input; this guards hand-edited config files,
/// where an invalid level would otherwise be passed straight to the zstd
/// C layer.
fn deserialize_zstd_level<'de, D>(deserializer: D) -> std::result::Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = u8::deserialize(deserializer)?;
    if ZSTD_LEVEL_RANGE.contains(&value) {
        Ok(value)
    } else {
        Err(serde::de::Error::custom(format!(
            "zstd_level must be 1-22, got {value}"
        )))
    }
}

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
    // Every serialized field carries an explicit default so a config file
    // written by an older 3.x release (before a field existed) still parses.
    #[serde(default = "default_use_zstd")]
    pub use_zstd: bool,
    /// zstd compression level (1-22). Default 3: on typical text data the
    /// ratio is within a few percent of higher levels at a vastly higher
    /// throughput (level does not affect the ciphertext format).
    #[serde(
        default = "default_zstd_level",
        deserialize_with = "deserialize_zstd_level"
    )]
    pub zstd_level: u8,
    /// list of files (patterns) to encrypt
    #[serde(default)]
    pub crypt_list: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            repo_path: PathBuf::from("."),
            config_path: PathBuf::from(CONFIG_FILE_NAME),
            use_zstd: DEFAULT_USE_ZSTD,
            zstd_level: DEFAULT_ZSTD_LEVEL,
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
    #[must_use]
    pub fn with_repo_path(mut self, path: impl AsRef<Path>) -> Self {
        let path = path.as_ref();
        self.repo_path = path.to_path_buf();
        self.config_path = path.join(CONFIG_FILE_NAME);
        self
    }

    /// Add one path to crypt list.
    ///
    /// `path` may be either relative or absolute (it will be resolved against
    /// `repo_path`). Returns an error if the path does not exist or cannot be
    /// expressed as a repo-relative path.
    ///
    /// Rejected outright: the repository root itself (`add .` would put every
    /// file including `.git` on the list), anything inside `.git`, and paths
    /// escaping the repository (`..`-laden relatives or absolute paths
    /// elsewhere — `e` must never encrypt files outside the repo).
    pub fn add_one_path_to_crypt_list(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        debug!("adding path to crypt list: {}", path.display());
        match path_relative_to(path, &self.repo_path) {
            PathRelativeTo::Outside(offending) => {
                Err(Error::PathNotRelative(offending.fuck_backslash()))
            },
            PathRelativeTo::Root => Err(Error::Other(format!(
                "refusing to add `{}`: the repository root itself cannot go on the crypt list; \
                 add specific files or directories instead",
                path.display()
            ))),
            PathRelativeTo::Inside(relative) => {
                let absolute = self.repo_path.join(&relative);
                debug!(
                    "path diff: {} to {}",
                    absolute.display(),
                    self.repo_path.display()
                );
                if !absolute.exists() {
                    return Err(Error::PathNotExist(absolute));
                }
                if has_git_component(&relative) {
                    return Err(Error::Other(format!(
                        "refusing to add `{}`: paths inside .git are git internals and must never \
                         be encrypted",
                        relative.display()
                    )));
                }
                if relative == Path::new(CONFIG_FILE_NAME) {
                    return Err(Error::Other(format!(
                        "refusing to add `{CONFIG_FILE_NAME}`: encrypting the tool's own config \
                         would make every later command (including decrypt) fail to load it",
                    )));
                }
                let path_str = relative.fuck_backslash().to_string_lossy().into_owned();
                // Entries are stored as repo-relative `/`-separated lossy strings;
                // compare in exactly that form so a path never enters the list twice
                // (duplicates would inflate the skip count and dirty the config).
                if self.crypt_list.contains(&path_str) {
                    debug!("already in crypt list, skipping: {path_str}");
                    return Ok(());
                }
                info!("Add to encrypt list: {}", path_str.green());
                self.crypt_list.push(path_str);
                Ok(())
            },
        }
    }

    /// Add the given paths to the encrypt list. This function will be called
    /// seldomly, so it's not a performance issue.
    pub fn add_paths_to_crypt_list(&mut self, paths: &[impl AsRef<Path>]) -> Result<()> {
        for x in paths {
            self.add_one_path_to_crypt_list(x.as_ref())?;
        }
        debug!("store config to {}", self.config_path.display());
        self.save().map_err(|e| Error::Config(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::{assert, fs};

    use config_file2::LoadConfigFile;
    use tempfile::TempDir;

    use super::*;

    fn load(file: impl AsRef<Path>) -> Result<Config> {
        Config::load_or_default(file).map_err(|e| Error::Config(e.to_string()))
    }

    fn temp_config() -> Result<(TempDir, Config)> {
        let temp_dir = TempDir::new()?;
        let config = load(temp_dir.path().join("test.toml"))?.with_repo_path(temp_dir.path());
        Ok((temp_dir, config))
    }

    #[test]
    fn test_add_one_file_to_crypt_list() -> Result<()> {
        let (temp_dir, mut config) = temp_config()?;

        let path_to_add = temp_dir.path().join("testdir");
        fs::create_dir(&path_to_add)?;
        config.add_one_path_to_crypt_list(path_to_add.as_os_str().to_string_lossy().as_ref())?;
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
    fn test_add_duplicate_path_to_crypt_list() -> Result<()> {
        let (temp_dir, mut config) = temp_config()?;

        fs::create_dir(temp_dir.path().join("testdir"))?;
        for _ in 0..2 {
            config.add_one_path_to_crypt_list(
                temp_dir
                    .path()
                    .join("testdir")
                    .as_os_str()
                    .to_string_lossy()
                    .as_ref(),
            )?;
        }
        assert_eq!(config.crypt_list, vec!["testdir".to_string()]);
        Ok(())
    }

    #[test]
    fn test_add_rejects_repo_root_and_git_internals() -> Result<()> {
        let (temp_dir, mut config) = temp_config()?;

        fs::create_dir_all(temp_dir.path().join(".git"))?;
        fs::write(temp_dir.path().join(".git").join("config"), "[core]")?;

        for bad in ["", ".", "./", ".git", ".git/config", "sub/.git/hooks"] {
            assert!(
                config.add_one_path_to_crypt_list(bad).is_err(),
                "adding {bad:?} must be rejected"
            );
        }
        // The tool's own config must not be put on the crypt list either.
        fs::write(temp_dir.path().join(CONFIG_FILE_NAME), "use_zstd = true")?;
        assert!(config.add_one_path_to_crypt_list(CONFIG_FILE_NAME).is_err());
        // The absolute repo root is the same case as `.`.
        assert!(config.add_one_path_to_crypt_list(temp_dir.path()).is_err());
        assert_eq!(config.crypt_list, Vec::<String>::new());
        Ok(())
    }

    #[test]
    fn test_add_rejects_paths_escaping_the_repo() -> Result<()> {
        let (_temp_dir, mut config) = temp_config()?;
        // The escape check runs before the existence check, so these are
        // rejected as escapes even though they do not exist.
        for escaping in ["../outside", "..", "../.."] {
            assert!(
                matches!(
                    config.add_one_path_to_crypt_list(escaping),
                    Err(Error::PathNotRelative(_))
                ),
                "adding {escaping:?} must be rejected as an escape"
            );
        }
        // A real sibling directory reached via `..` hits the same check.
        let sibling = TempDir::new()?;
        let name = sibling.path().file_name().unwrap().to_owned();
        assert!(matches!(
            config.add_one_path_to_crypt_list(Path::new("..").join(name)),
            Err(Error::PathNotRelative(_))
        ));
        assert_eq!(config.crypt_list, Vec::<String>::new());
        Ok(())
    }

    #[test]
    fn test_config_loads_with_missing_fields() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let file = temp_dir.path().join("test.toml");

        // Every serialized field may be absent; the documented defaults
        // apply (forward compatibility inside the 3.x series).
        fs::write(&file, "zstd_level = 9\n")?;
        let conf = load(&file)?;
        assert_eq!(conf.zstd_level, 9);
        assert!(conf.use_zstd);
        assert_eq!(conf.crypt_list, Vec::<String>::new());

        fs::write(&file, "use_zstd = false\n")?;
        let conf = load(&file)?;
        assert!(!conf.use_zstd);
        assert_eq!(conf.zstd_level, DEFAULT_ZSTD_LEVEL);
        assert_eq!(conf.crypt_list, Vec::<String>::new());

        fs::write(&file, "crypt_list = [\"a\"]\n")?;
        let conf = load(&file)?;
        assert_eq!(conf.crypt_list, vec!["a".to_string()]);
        assert_eq!(conf.zstd_level, DEFAULT_ZSTD_LEVEL);
        assert!(conf.use_zstd);

        // A completely empty file is all-defaults.
        fs::write(&file, "")?;
        let conf = load(&file)?;
        assert_eq!(conf.zstd_level, DEFAULT_ZSTD_LEVEL);
        assert!(conf.use_zstd);
        assert_eq!(conf.crypt_list, Vec::<String>::new());
        Ok(())
    }

    #[test]
    fn test_config_rejects_out_of_range_zstd_level() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let file = temp_dir.path().join("test.toml");

        for bad in [0_u8, 23, 255] {
            fs::write(&file, format!("zstd_level = {bad}\n"))?;
            let err = load(&file).unwrap_err().to_string();
            assert!(err.contains("zstd_level"), "got: {err}");
        }

        // Boundary values stay valid.
        fs::write(&file, "zstd_level = 1\n")?;
        assert_eq!(load(&file)?.zstd_level, 1);
        fs::write(&file, "zstd_level = 22\n")?;
        assert_eq!(load(&file)?.zstd_level, 22);
        Ok(())
    }
}
