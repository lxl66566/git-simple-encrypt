use super::{ATTR_NAME, GIT_ATTRIBUTES, KEY_NAME};
use crate::cli::CLI;
use crate::utils::BetterStripPrefix;
use colored::Colorize;
use die_exit::DieWith;
use git2::{AttrCheckFlags, IndexAddOption, Repository};
use log::debug;
use same_file::is_same_file;
use std::path::PathBuf;
use std::sync::LazyLock as Lazy;
use std::sync::Mutex;
use tap::Tap;

pub static REPO: Lazy<Mutex<Repository>> = Lazy::new(|| {
    let repo = Repository::open(&CLI.repo).die_with(|e| format!("Failed to open repository: {e}"));
    debug!("Opened repository: {:?}", repo.path());
    Mutex::new(repo)
});

#[cfg(not(test))]
pub static KEY: Lazy<String> = Lazy::new(|| {
    use super::KEY_NAME;
    use die_exit::Die;
    REPO.lock()
        .unwrap()
        .config()
        .die("Cannot get config from this repo.")
        .get_string(KEY_NAME)
        .die_with(|e| format!("KEY is empty: {e}"))
});
#[cfg(test)]
pub static KEY: Lazy<String> = Lazy::new(|| "123".into());

/// tracking https://github.com/rust-lang/git2-rs/issues/1048
pub trait Git2Patch {
    fn patch(self) -> Self;
}
impl Git2Patch for PathBuf {
    fn patch(mut self) -> Self {
        self.strip_prefix_better("./").strip_prefix_better(".\\");
        self
    }
}

#[inline]
pub fn add_all() -> anyhow::Result<()> {
    let mut index = REPO.lock().unwrap().index()?;
    index.add_all(std::iter::once(&"*"), IndexAddOption::DEFAULT, None)?;
    index.write()?;
    Ok(())
}

pub fn need_crypt(mut path: PathBuf) -> anyhow::Result<Option<PathBuf>> {
    if is_same_file(&path, GIT_ATTRIBUTES.as_path())? {
        println!(
            "{}",
            "Warning: cannot encrypt `.gitattributes` file.".yellow()
        );
        return Ok(None);
    }
    path = path.patch();
    debug!("checking file: {:?}", path);
    Ok(REPO
        .lock()
        .unwrap()
        .get_attr_bytes(&path, ATTR_NAME, AttrCheckFlags::default())?
        .tap(|x| debug!("attr: {:?}", x))
        .map(|_| path))
}

pub fn set_key(key: &str) -> anyhow::Result<()> {
    REPO.lock().unwrap().config()?.set_str(KEY_NAME, key)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[compio::test]
    async fn test_need_crypt() {
        let file = PathBuf::from(".").join("tests/test.txt");
        std::assert!(need_crypt(file).unwrap().is_some());
        let file = PathBuf::from(".").join("tests");
        std::assert!(need_crypt(file).unwrap().is_none());
    }
}
