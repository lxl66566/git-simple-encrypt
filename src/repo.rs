use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use assert2::assert;
use log::debug;
use tap::Tap;

use crate::{
    config::{Config, CONFIG_FILE},
    utils::PathToAbsolute,
};

pub const GIT_CONFIG_PREFIX: &str =
    const_str::replace!(concat!(env!("CARGO_CRATE_NAME"), "."), "_", "-");

#[derive(Debug, Clone)]
pub struct Repo {
    pub path: PathBuf,
    pub conf: Config,
}

impl Repo {
    /// open a repo. The [`path`] of repo will be processed to absolute path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut path = path.as_ref().to_path_buf().absolute();
        assert!(path.exists(), "Repo not found: {}", path.display());
        assert!(path.is_dir(), "Not a directory: {}", path.display());
        if path
            .file_name()
            .ok_or_else(|| anyhow!("Filename not found"))?
            == ".git"
        {
            path.pop();
        }
        println!("Open repo: {}", path.display());
        let conf = Config::load_or_create_from(path.join(CONFIG_FILE));
        Ok(Self { path, conf })
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn to_absolute_path(&self, path: impl AsRef<Path>) -> PathBuf {
        self.path.join(path.as_ref()).absolute()
    }
    pub fn ls_files_with_given_patterns(&self, patterns: &[&str]) -> Result<Vec<String>> {
        let files_zip: Result<Vec<Vec<String>>> =
            patterns.iter().map(|&x| self.ls_files(&[x])).collect();
        Ok(files_zip?.into_iter().flatten().collect())
    }
    pub fn ls_files_absolute_with_given_patterns(&self, patterns: &[&str]) -> Result<Vec<PathBuf>> {
        debug!("ls_files_absolute_with_given_patterns: {:?}", patterns);
        let files_zip: Result<Vec<Vec<PathBuf>>> = patterns
            .iter()
            .map(|&x| self.ls_files_absolute(&[x]))
            .collect();
        Ok(files_zip?.into_iter().flatten().collect())
    }
    pub fn get_key(&self) -> Result<String> {
        self.get_config("key")
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
            .split(|c| c == '\0')
            .map(|s| s.to_string())
            .collect();
        debug!("ls-files: {:?}", files);
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

    use temp_testdir::TempDir;

    use super::*;

    #[test]
    fn test_repo_open() -> Result<()> {
        let repo = Repo::open(".")?;
        assert_eq!(repo.path().file_name().unwrap(), "git-simple-encrypt");
        let repo = Repo::open("./.git")?;
        assert_eq!(repo.path().file_name().unwrap(), "git-simple-encrypt");
        Ok(())
    }

    #[test]
    fn test_repo_gitcommand() -> Result<()> {
        let temp_dir = TempDir::default();
        let repo = Repo::open(&temp_dir)?;
        repo.run(&["init"])?;
        assert!(temp_dir.join(".git").is_dir());
        let temp = repo.ls_files(&[])?;
        assert!(temp.is_empty(), "repo not empty: {:?}", temp);
        fs::File::create(temp_dir.join("test.txt"))?;
        repo.add_all()?;
        assert!(repo
            .run_with_output(&["status"])?
            .contains("Changes to be committed"));
        assert!(repo.ls_files(&[]).unwrap().contains(&"test.txt".into()));
        assert_eq!(
            repo.ls_files_absolute(&[])
                .unwrap()
                .into_iter()
                .find(|x| x.file_name().unwrap() == "test.txt")
                .unwrap()
                .absolute(),
            temp_dir.join("test.txt").absolute()
        );

        repo.set_config("test", "test1")?;
        assert_eq!(repo.get_config("test")?, "test1");
        Ok(())
    }
}
