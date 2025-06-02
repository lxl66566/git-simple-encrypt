use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
};

use anyhow::{Result, anyhow};
use assert2::assert;
#[cfg(any(test, debug_assertions))]
use colored::Colorize;
use config_file2::LoadConfigFile;
use log::{debug, info, warn};
use path_absolutize::Absolutize;
use tap::Tap;

use crate::{
    config::{CONFIG_FILE_NAME, Config},
    crypt::calculate_key_sha,
    utils::prompt_password,
};

pub const GIT_CONFIG_PREFIX: &str =
    const_str::replace!(concat!(env!("CARGO_CRATE_NAME"), "."), "_", "-");

#[derive(Debug, Clone, Default)]
pub struct Repo {
    /// The absolute path of the opened repo.
    pub path: PathBuf,
    pub conf: Config,
    pub key_sha: OnceLock<Box<[u8]>>,
}

impl Repo {
    /// open a repo. The [`path`] of repo will be processed to absolute path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut repo_path = path
            .as_ref()
            .absolutize()
            .expect("path absolutize failed")
            .to_path_buf();
        assert!(repo_path.is_absolute(), "given path must be absolute");
        assert!(
            repo_path.exists(),
            "Repo not found: {}",
            repo_path.display()
        );
        assert!(
            repo_path.is_dir(),
            "Not a directory: {}",
            repo_path.display()
        );
        if repo_path
            .file_name()
            .ok_or_else(|| anyhow!("Filename not found"))?
            == ".git"
        {
            repo_path.pop();
        }
        info!("Open repo: {}", repo_path.display());
        let config_file_path = repo_path.join(CONFIG_FILE_NAME);
        if !config_file_path.exists() {
            warn!(
                "Config file not found: `{}`, using default config instead...",
                config_file_path.display()
            );
        }
        let mut conf = Config::load_or_default(config_file_path)?;
        conf.repo_path.clone_from(&repo_path);
        Ok(Self {
            path: repo_path,
            conf,
            key_sha: OnceLock::new(),
        })
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn to_absolute_path(&self, path: impl AsRef<Path>) -> PathBuf {
        self.path.join(path.as_ref())
    }
    pub fn ls_files_with_given_patterns(&self, patterns: &[&str]) -> Result<Vec<String>> {
        let files_zip: Result<Vec<Vec<String>>> =
            patterns.iter().map(|&x| self.ls_files(&[x])).collect();
        Ok(files_zip?.into_iter().flatten().collect())
    }
    pub fn ls_files_absolute_with_given_patterns(&self, patterns: &[&str]) -> Result<Vec<PathBuf>> {
        debug!("ls_files_absolute_with_given_patterns: {patterns:?}");
        let files_zip: Result<Vec<Vec<PathBuf>>> = patterns
            .iter()
            .map(|&x| self.ls_files_absolute(&[x]))
            .collect();
        Ok(files_zip?.into_iter().flatten().collect())
    }
    pub fn get_key(&self) -> String {
        self.get_config("key")
            .expect("Key not found, please exec `git-se p` first.")
    }

    /// returns the first 16 bytes of sha3-224 of the key.
    /// The sha result will only be calculated once in the lifetime of the
    /// object.
    pub fn get_key_sha(&self) -> &[u8] {
        self.key_sha.get_or_init(|| {
            let key = self.get_key();
            #[cfg(any(test, debug_assertions))]
            println!("Key: {}", key.green());
            let hash_result = calculate_key_sha(key);
            let hash_result_slice = hash_result.as_slice();
            #[cfg(any(test, debug_assertions))]
            {
                use crate::utils::format_hex;
                println!("Hash Cut result: {}", format_hex(hash_result_slice).green());
            }
            hash_result_slice.into()
        })
    }

    /// set the key interactively
    pub fn set_key_interactive(&self) -> Result<()> {
        let key = prompt_password("Please input your key: ")?;
        self.set_config("key", &key)?;
        info!("Set key: `{key}`");
        Ok(())
    }
}

pub trait GitCommand {
    fn run(&self, args: &[&str]) -> Result<()>;
    fn run_with_output(&self, args: &[&str]) -> Result<String>;
    fn add_all(&self) -> Result<()>;
    fn ls_files(&self, args: &[&str]) -> Result<Vec<String>>;
    fn ls_files_absolute(&self, args: &[&str]) -> Result<Vec<PathBuf>>;
    fn set_config(&self, key: &str, value: &str) -> Result<()>;
    fn get_config(&self, key: &str) -> Result<String>;
}

impl GitCommand for Repo {
    fn run(&self, args: &[&str]) -> Result<()> {
        let output = std::process::Command::new("git")
            .current_dir(&self.path)
            .args(args)
            .output()?;
        if !output.status.success() {
            return Err(anyhow!(
                "Git command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(())
    }
    fn run_with_output(&self, args: &[&str]) -> Result<String> {
        let mut cmd = std::process::Command::new("git");

        // we need to check English output in test
        if cfg!(test) {
            cmd.env("LC_ALL", "C.UTF-8").env("LANGUAGE", "C.UTF-8");
        }

        let output = cmd.current_dir(&self.path).args(args).output()?;
        if !output.status.success() {
            return Err(anyhow!(
                "Git command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(String::from_utf8(output.stdout)?)
    }
    fn add_all(&self) -> Result<()> {
        self.run(&["add", "-A"])
    }
    /// `git ls-files` with given args, mostly with a wildcard pattern.
    fn ls_files(&self, args: &[&str]) -> Result<Vec<String>> {
        let output =
            self.run_with_output(&vec!["ls-files", "-z"].tap_mut(|x| x.extend_from_slice(args)))?;
        let output_processed = output.trim().trim_matches('\0');
        if output_processed.is_empty() {
            return Ok(vec![]);
        }
        let files = output_processed
            .split('\0')
            .map(std::string::ToString::to_string)
            .collect();
        debug!("ls-files: {files:?}");
        Ok(files)
    }
    /// returns the absolute path of `ls-files`.
    fn ls_files_absolute(&self, args: &[&str]) -> Result<Vec<PathBuf>> {
        Ok(self
            .ls_files(args)?
            .into_iter()
            .map(|f| self.to_absolute_path(f))
            .collect())
    }
    fn set_config(&self, key: &str, value: &str) -> Result<()> {
        let temp = String::from(GIT_CONFIG_PREFIX) + key;
        self.run(&["config", "--local", &temp, value.trim()])
    }
    fn get_config(&self, key: &str) -> Result<String> {
        let temp = String::from(GIT_CONFIG_PREFIX) + key;
        self.run_with_output(&["config", "--get", &temp])
            .map(|x| x.trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::{assert, fs};

    use path_absolutize::Absolutize;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_repo_open() -> Result<()> {
        let repo = Repo::open(Path::new("."))?;
        assert_eq!(repo.path().file_name().unwrap(), "git-simple-encrypt");
        let repo = Repo::open(Path::new("./.git"))?;
        assert_eq!(repo.path().file_name().unwrap(), "git-simple-encrypt");
        Ok(())
    }

    #[test]
    fn test_repo_gitcommand() -> Result<()> {
        let temp_dir = TempDir::new()?.keep();
        let repo = Repo::open(&temp_dir)?;
        repo.run(&["init"])?;
        assert!(temp_dir.join(".git").is_dir());
        let temp = repo.ls_files(&[])?;
        assert!(temp.is_empty(), "repo not empty: {temp:?}");
        fs::File::create(temp_dir.join("test.txt"))?;
        repo.add_all()?;
        assert!(
            repo.run_with_output(&["status"])?
                .contains("Changes to be committed")
        );
        assert!(repo.ls_files(&[]).unwrap().contains(&"test.txt".into()));
        assert_eq!(
            repo.ls_files_absolute(&[])
                .unwrap()
                .into_iter()
                .find(|x| x.file_name().unwrap() == "test.txt")
                .unwrap()
                .absolutize()
                .expect("path absolutize failed")
                .as_ref(),
            temp_dir
                .join("test.txt")
                .absolutize()
                .expect("path absolutize failed")
                .as_ref()
        );

        repo.set_config("test", "test1")?;
        assert_eq!(repo.get_config("test")?, "test1");
        Ok(())
    }
}
