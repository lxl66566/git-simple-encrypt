use crate::cli::CLI;
use crate::crypt::{decrypt_file, encrypt_file, ENCRYPTED_EXTENSION};
use crate::utils::{bytes2path, AppendExt};
use colored::Colorize;
use die_exit::DieWith;
use futures_util::future::join_all;
use git2::{AttrCheckFlags, IndexAddOption, Repository};
use log::debug;
use std::path::PathBuf;
use std::sync::{LazyLock as Lazy, Mutex};

const KEY_NAME: &str = "simple-git-encrypt.key";
const ATTR_NAME: &str = "crypt";
pub static REPO: Lazy<Mutex<Repository>> = Lazy::new(|| {
    let repo = Repository::open(
        #[cfg(not(test))]
        &CLI.repo,
        #[cfg(test)]
        ".",
    )
    .die_with(|e| format!("Failed to open repository: {e}"));
    Mutex::new(repo)
});

#[cfg(not(test))]
pub static KEY: Lazy<String> = Lazy::new(|| {
    use die_exit::Die;
    REPO.lock()
        .unwrap()
        .config()
        .die("Cannot get config from this repo.")
        .get_string(KEY_NAME)
        .die_with(|e| format!("KEY is empty: {e}"))
});
#[cfg(test)]
pub static KEY: Lazy<String> = Lazy::new(|| "test-key".into());

pub fn set_key(key: &str) -> anyhow::Result<()> {
    REPO.lock().unwrap().config()?.set_str(KEY_NAME, key)?;
    Ok(())
}

#[inline]
fn add_all() -> anyhow::Result<()> {
    let mut index = REPO.lock().unwrap().index()?;
    index.add_all(["*"].iter(), IndexAddOption::DEFAULT, None)?;
    index.write()?;
    Ok(())
}

#[inline]
fn need_crypt(path: PathBuf) -> anyhow::Result<Option<PathBuf>> {
    debug!("checking file: {:?}", path);
    Ok(REPO
        .lock()
        .unwrap()
        .get_attr_bytes(&path, ATTR_NAME, AttrCheckFlags::default())?
        .map(|_| path))
}

pub async fn encrypt_repo() -> anyhow::Result<()> {
    add_all()?;
    let lock = REPO.lock().unwrap().index()?;
    let encrypt_futures = lock
        .iter()
        .map(|x| CLI.repo.join(bytes2path(&x.path)))
        .filter_map(|x| need_crypt(x).ok().flatten())
        .map(encrypt_file);
    join_all(encrypt_futures).await.into_iter().for_each(|x| {
        if let Err(err) = x {
            println!(
                "{}",
                format!("warning: failed to encrypt file: {}", err).yellow()
            )
        }
    });
    add_all()?;
    Ok(())
}

pub async fn decrypt_repo() -> anyhow::Result<()> {
    let lock = REPO.lock().unwrap().index()?;
    let decrypt_futures = lock
        .iter()
        .map(|x| CLI.repo.join(bytes2path(&x.path)))
        .filter(|x| x.extension().unwrap_or_default() == ENCRYPTED_EXTENSION)
        .filter_map(|x| {
            need_crypt(x.with_extension(""))
                .ok()
                .flatten()
                .map(|x| x.append_ext())
        })
        .map(decrypt_file);
    join_all(decrypt_futures).await.into_iter().for_each(|x| {
        if let Err(err) = x {
            println!(
                "{}",
                format!("warning: failed to decrypt file: {}", err).yellow()
            )
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[compio::test]
    async fn test_need_crypt() {
        let file = PathBuf::from(".").join("tests/test.txt");
        assert!(need_crypt(file.clone()).unwrap().is_some());
    }
}
