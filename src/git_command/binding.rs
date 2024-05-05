//! The code of git2_rs bindings.

use std::{
    path::{Path},
    sync::{LazyLock as Lazy, Mutex},
};

use anyhow::Ok;
use die_exit::DieWith;
use git2::{AttrCheckFlags, IndexAddOption, Repository};
use log::debug;
use tap::Tap;

use super::ATTR_NAME;
use crate::{cli::CLI, utils::Git2Patch};

pub static REPO: Lazy<Mutex<Repository>> = Lazy::new(|| {
    let repo = Repository::open(&CLI.repo).die_with(|e| format!("Failed to open repository: {e}"));
    debug!("Opened repository: {:?}", repo.path());
    Mutex::new(repo)
});

#[inline]
pub fn add_all() -> anyhow::Result<()> {
    let mut index = REPO.lock().unwrap().index()?;
    index.add_all(std::iter::once(&"*"), IndexAddOption::DEFAULT, None)?;
    index.write()?;
    Ok(())
}

#[allow(dead_code)]
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
