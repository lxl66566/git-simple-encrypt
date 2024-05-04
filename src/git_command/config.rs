use std::sync::LazyLock as Lazy;

use colored::Colorize;
use die_exit::{die, Die};

use super::REPO;

const FIELDNAME: &str = "simple-git-encrypt";

#[cfg(not(test))]
pub static CONFIG: Lazy<Config> = Lazy::new(Config::read);
#[cfg(test)]
pub static CONFIG: Lazy<Config> = Lazy::new(Default::default);

#[derive(Debug, Clone)]
pub enum ConfigValue {
    Key(String),
    ZstdLevel(i32),
}

impl ConfigValue {
    pub const fn to_field(&self) -> ConfigField {
        match self {
            Self::Key(_) => ConfigField::Key,
            Self::ZstdLevel(_) => ConfigField::ZstdLevel,
        }
    }
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum ConfigField {
    Key,
    ZstdLevel,
}

impl ConfigField {
    pub fn name(&self) -> &'static str {
        let concat = |s: &str| Box::new(format!("{}.{}", FIELDNAME, s)).leak();
        match self {
            Self::Key => concat("key"),
            Self::ZstdLevel => concat("zstd-level"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub key: String,
    pub zstd_level: i32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            key: "123".into(),
            zstd_level: 15,
        }
    }
}

impl Config {
    #[cfg(not(test))]
    pub fn read() -> Self {
        let config = REPO
            .lock()
            .unwrap()
            .config()
            .die("Cannot get config from this repo.");
        Self {
            key: config
                .get_string(ConfigField::Key.name())
                .unwrap_or(Self::default().key),
            zstd_level: config
                .get_i32(ConfigField::ZstdLevel.name())
                .unwrap_or(Self::default().zstd_level),
        }
    }
    pub fn save(&self) -> anyhow::Result<()> {
        let mut config = REPO.lock().unwrap().config()?;
        config.set_str(ConfigField::Key.name(), &self.key)?;
        config.set_i32(ConfigField::ZstdLevel.name(), self.zstd_level)?;
        Ok(())
    }
    pub fn set(&self, value: ConfigValue) -> anyhow::Result<()> {
        let mut config = REPO.lock().unwrap().config()?;
        match &value {
            ConfigValue::Key(key) => {
                config.set_str(value.to_field().name(), key)?;
            }
            ConfigValue::ZstdLevel(level) => {
                config.set_i32(value.to_field().name(), *level)?;
            }
        }
        Ok(())
    }
}

pub fn set(field: &str, value: &str) -> anyhow::Result<()> {
    CONFIG.save()?;
    match field {
        "key" => {
            CONFIG.set(ConfigValue::Key(value.to_owned()))?;
        }
        "zstd-level" => {
            let value = value.parse::<i32>().die("zstd-level must be an integer");
            CONFIG.set(ConfigValue::ZstdLevel(value))?;
        }
        field => die!("unknown field: {}", field),
    };
    println!(
        "{}",
        format!("Successfully set `{}` to `{}`", field, value).green()
    );
    Ok(())
}

pub fn set_key(key: &str) -> anyhow::Result<()> {
    set("key", key)?;
    Ok(())
}
