use std::path::{Path, PathBuf};

use colored::Colorize;
use die_exit::die;
use serde::{Deserialize, Serialize};

pub const CONFIG_FILE: &str = concat!(env!("CARGO_CRATE_NAME"), ".toml");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub path: PathBuf,
    pub use_zstd: bool,
    pub zstd_level: u8,
    pub crypt_list: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            path: PathBuf::from(CONFIG_FILE),
            use_zstd: true,
            zstd_level: 15,
            crypt_list: vec![],
        }
    }
}

impl Config {
    pub fn with_path(mut self, path: impl AsRef<Path>) -> Self {
        self.path = path.as_ref().to_path_buf();
        self
    }
    pub fn default_with_path(path: impl AsRef<Path>) -> Self {
        Self::default().with_path(path)
    }
    pub fn load(&self) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(&self.path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
    pub fn save(&self) -> anyhow::Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(&self.path, content)?;
        Ok(())
    }
    pub fn load_or_create(self) -> Self {
        let loaded = self.load();
        if let Ok(config) = loaded {
            config
        } else {
            eprintln!(
                "{}",
                format!(
                    "Warning: config not found in {}, use default...",
                    self.path.display()
                )
                .yellow()
            );
            let config = Self::default();
            config
                .save()
                .unwrap_or_else(|e| die!("Failed to save config file: {}", e));
            config
        }
    }
    pub fn add_to_crypt_list_one(&mut self, path: &str) {
        let p = Path::new(path);
        debug_assert!(p.exists());
        self.crypt_list
            .push(path.to_string() + if p.is_dir() { "/**" } else { "" });
    }
    pub fn add_to_crypt_list(&mut self, paths: &[&str]) {
        paths
            .into_iter()
            .for_each(|x| self.add_to_crypt_list_one(x));
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use temp_testdir::TempDir;

    use super::*;

    #[test]
    fn test() -> anyhow::Result<()> {
        let temp_dir = TempDir::default();
        let mut config = Config::default_with_path(temp_dir.join("test")).load_or_create();
        assert!(config == Config::default());
        assert!(temp_dir.join("test").exists());

        fs::create_dir(temp_dir.join("123"));
        config.add_to_crypt_list_one(temp_dir.join("123").as_os_str().to_string_lossy().as_ref());
        config.save();

        let config = Config::default_with_path(temp_dir.join("test")).load()?;
        assert!(config.crypt_list[0].ends_with("/**"));
        Ok(())
    }
}
