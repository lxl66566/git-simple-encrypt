use std::sync::LazyLock as Lazy;

use die_exit::{die, Die};

use super::REPO;

const FIELD: &str = "simple-git-encrypt";

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
    pub fn name(&self) -> &'static str {
        let concat = |s: &str| Box::new(format!("{}.{}", FIELD, s)).leak();
        match self {
            Self::Key(_) => concat("key"),
            Self::ZstdLevel(_) => concat("zstd_level"),
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
                .get_string(ConfigValue::Key(Default::default()).name())
                .unwrap_or_default(),
            zstd_level: config
                .get_i32(ConfigValue::ZstdLevel(Default::default()).name())
                .unwrap_or_default(),
        }
    }
    pub fn save(&self) -> anyhow::Result<()> {
        let mut config = REPO.lock().unwrap().config()?;
        config.set_str(ConfigValue::Key(Default::default()).name(), &self.key)?;
        config.set_i32(
            ConfigValue::ZstdLevel(Default::default()).name(),
            self.zstd_level,
        )?;
        Ok(())
    }
    pub fn set(&self, value: ConfigValue) -> anyhow::Result<()> {
        let mut config = REPO.lock().unwrap().config()?;
        match &value {
            ConfigValue::Key(key) => {
                config.set_str(value.name(), key)?;
            }
            ConfigValue::ZstdLevel(level) => {
                config.set_i32(value.name(), *level)?;
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
        "zstd_level" => {
            let value = value.parse::<i32>().die("zstd_level must be an integer");
            CONFIG.set(ConfigValue::ZstdLevel(value))?;
        }
        field => die!("unknown field: {}", field),
    };
    Ok(())
}
