use std::{
    path::{Path, PathBuf},
    sync::{LazyLock as Lazy, Mutex},
};

use anyhow::Ok;
use colored::Colorize;
use die_exit::DieWith;
use git2::{AttrCheckFlags, IndexAddOption, Repository};
use log::debug;
use same_file::is_same_file;
use tap::Tap;

use super::{ATTR_NAME, GIT_ATTRIBUTES};
use crate::{
    cli::CLI,
    crypt::{COMPRESSED_EXTENSION, ENCRYPTED_EXTENSION},
    utils::BetterStripPrefix,
};

pub static REPO: Lazy<Mutex<Repository>> = Lazy::new(|| {
    let repo = Repository::open(&CLI.repo).die_with(|e| format!("Failed to open repository: {e}"));
    debug!("Opened repository: {:?}", repo.path());
    Mutex::new(repo)
});

/// tracking https://github.com/rust-lang/git2-rs/issues/1048
pub trait Git2Patch {
    fn patch(&self) -> PathBuf;
}
impl<T: AsRef<Path>> Git2Patch for T {
    fn patch(&self) -> PathBuf {
        self.as_ref()
            .to_path_buf()
            .tap_mut(|x| {
                x.strip_prefix_better("./");
            })
            .tap_mut(|x| {
                x.strip_prefix_better(".\\");
            })
    }
}

#[inline]
pub fn add_all() -> anyhow::Result<()> {
    let mut index = REPO.lock().unwrap().index()?;
    index.add_all(std::iter::once(&"*"), IndexAddOption::DEFAULT, None)?;
    index.write()?;
    Ok(())
}

pub fn check_attr(path: impl AsRef<Path>) -> anyhow::Result<bool> {
    let path = path.patch();
    Ok(REPO
        .lock()
        .unwrap()
        .get_attr_bytes(&path, ATTR_NAME, AttrCheckFlags::default())?
        .tap(|attr| debug!("check-attr for file `{:?}`: {:?}", path, attr))
        .is_some())
}

// #[cached::proc_macro::cached]
// pub fn check_attr(path: PathBuf) -> bool {
//     let path = path.patch();
//     REPO.lock()
//         .unwrap()
//         .get_attr_bytes(&path, ATTR_NAME, AttrCheckFlags::default())
//         .die_with(|e| format!("Error occurs when checking attr of `{:?}`:
// {e}", path))         .tap(|attr| debug!("check-attr for file `{:?}`: {:?}",
// path, attr))         .is_some()
// }

pub fn need_encrypt(path: impl AsRef<Path>) -> anyhow::Result<bool> {
    let path = path.as_ref();
    if path.exists() && is_same_file(path, GIT_ATTRIBUTES.as_path())? {
        println!(
            "{}",
            "Warning: cannot encrypt `.gitattributes` file.".yellow()
        );
        return Ok(false);
    }
    let path = path.patch();
    debug!("checking whether `{:?}` needs encrypt", path);
    check_attr(path)
}

/// If file extension matches, check recursively; Otherwise check once.
pub fn need_decrypt(path: impl AsRef<Path>) -> anyhow::Result<bool> {
    let path = path.as_ref();
    debug!("checking whether `{:?}` needs decrypt", path);
    match path.extension() {
        Some(ext)
            if [ENCRYPTED_EXTENSION, COMPRESSED_EXTENSION]
                .into_iter()
                .any(|x| x == ext) =>
        {
            if check_attr(path)? {
                Ok(true)
            } else {
                need_decrypt(path.with_extension(""))
            }
        }
        _ => check_attr(path),
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[compio::test]
    async fn test_need_crypt() {
        let file = PathBuf::from(".").join("tests/test.txt");
        std::assert!(need_encrypt(file).unwrap());
        let file = PathBuf::from(".").join("tests");
        std::assert!(!need_encrypt(file).unwrap());
    }
}
