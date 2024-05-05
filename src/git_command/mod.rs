mod binding;
pub mod config;
mod manual_craft;

use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
    sync::LazyLock as Lazy,
};

use anyhow::Ok;
pub use binding::{add_all, REPO};
use colored::Colorize;
pub use config::CONFIG;
use die_exit::die;
use futures_util::{stream::FuturesOrdered, StreamExt};
use log::debug;
use regex::Regex;
use same_file::is_same_file;

use self::manual_craft::check_attr;
use crate::{
    cli::CLI,
    crypt::{decrypt_file, encrypt_file, COMPRESSED_EXTENSION, ENCRYPTED_EXTENSION},
    git_command::manual_craft::{add_attr, remove_attr},
    utils::{Git2Patch, PathFromBytes, PathToUnixStyle, END_OF_LINE},
};

const ATTR_NAME: &str = "crypt";
pub static GIT_ATTRIBUTES: Lazy<PathBuf> = Lazy::new(|| CLI.repo.join(".gitattributes"));

pub async fn encrypt_repo() -> anyhow::Result<()> {
    add_all()?;
    let lock = REPO.lock().unwrap().index()?;
    let mut encrypt_futures = lock
        .iter()
        .map(|x| CLI.repo.join(PathBuf::from_bytes(&x.path)))
        .filter(|x| x.is_file())
        .filter(|x| need_encrypt(x).unwrap_or(false))
        .map(encrypt_file)
        .collect::<FuturesOrdered<_>>();
    while let Some(ret) = encrypt_futures.next().await {
        if let Err(err) = ret {
            eprintln!(
                "{}",
                format!("warning: failed to encrypt file: {}", err).yellow()
            )
        }
    }
    add_all()?;
    Ok(())
}

pub async fn decrypt_repo() -> anyhow::Result<()> {
    let lock = REPO.lock().unwrap().index()?;
    let mut decrypt_futures = lock
        .iter()
        .map(|x| CLI.repo.join(PathBuf::from_bytes(&x.path)))
        .filter(|x| {
            [ENCRYPTED_EXTENSION, COMPRESSED_EXTENSION]
                .into_iter()
                .any(|y| y == x.extension().unwrap_or_default())
        })
        .filter(|x| x.is_file())
        .filter(|x| need_decrypt(x).unwrap_or(false))
        .map(decrypt_file)
        .collect::<FuturesOrdered<_>>();
    while let Some(ret) = decrypt_futures.next().await {
        if let Err(err) = ret {
            eprintln!(
                "{}",
                format!("warning: failed to decrypt file: {}", err).yellow()
            )
        }
    }
    add_all()?;
    Ok(())
}

pub fn need_encrypt(path: impl AsRef<Path>) -> anyhow::Result<bool> {
    let path = path.as_ref();
    if path.exists() && is_same_file(path, GIT_ATTRIBUTES.as_path())? {
        return Ok(false);
    }
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

/// add file/folder to .gitattributes, means it needs encrypt.
pub fn add_crypt_attributes(path: impl AsRef<Path>) -> anyhow::Result<()> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(GIT_ATTRIBUTES.as_path())?;
    let mut test_path = path.as_ref().to_owned();
    if test_path.is_dir() {
        test_path.push("any");
    }
    if need_encrypt(&test_path)? {
        println!("`{:?}` is already marked as encrypt-needed.", path.as_ref());
        #[cfg(not(test))]
        std::process::exit(0);
        #[cfg(test)]
        anyhow::bail!("`{:?}` is already marked as encrypt-needed.", path.as_ref());
    }
    let mut path = path.as_ref().patch();
    if path.is_dir() {
        path.push("**");
    }
    add_attr(path)?;
    debug_assert!(need_encrypt(test_path)?);
    Ok(())
}

pub fn remove_crypt_attributes(path: impl AsRef<Path>) -> anyhow::Result<()> {
    let mut test_path = path.as_ref().to_path_buf();
    if test_path.is_dir() {
        test_path.push("any");
    }
    if !need_encrypt(test_path)? {
        println!(
            "`{:?}` is already not marked as encrypt-needed.",
            path.as_ref()
        );
        #[cfg(not(test))]
        std::process::exit(0);
        #[cfg(test)]
        anyhow::bail!(
            "`{:?}` is already not marked as encrypt-needed.",
            path.as_ref()
        );
    }
    let content = std::fs::read_to_string(GIT_ATTRIBUTES.as_path())?;
    let mut content_vec: Vec<&str> = content.split('\n').collect();
    let re = Regex::new(&format!(
        r#"^(./)?{}(/\*\*)?\s"#,
        path.as_ref().to_unix_style().to_string_lossy()
    ))
    .expect("builtin regex should be valid.");
    let index = content_vec.iter().position(|line| re.is_match(line));
    let removed_attr: &str;
    if let Some(i) = index {
        let str_to_remove = content_vec[i].split_once(' ').unwrap().0.trim();
        removed_attr = content_vec.remove(i);
        remove_attr(str_to_remove);
    } else {
        die!("Cannot find the match attribute. You can delete this attribute by editing `.gitattributes`.")
    }
    content_vec.pop_if(|line| line.trim().is_empty());
    std::fs::write(GIT_ATTRIBUTES.as_path(), content_vec.join(END_OF_LINE))?;
    debug_assert!(!need_encrypt(path)?);
    println!("Removed attribute: `{}`", removed_attr.red());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[compio::test]
    async fn test_need_encrypt() {
        let file = PathBuf::from(".").join("test_assets/test.txt");
        std::assert!(need_encrypt(file).unwrap());
        let file = PathBuf::from(".").join("tests");
        std::assert!(!need_encrypt(file).unwrap());
        let file = PathBuf::from(".").join("tests").join("any");
        std::assert!(!need_encrypt(file).unwrap());
    }

    #[test]
    fn test_add_remove_attr() -> anyhow::Result<()> {
        env_logger::init();
        let read = || {
            // sleep, otherwise the read() access will be denied. (git2_rs call has delay)
            std::thread::sleep(std::time::Duration::from_millis(20));
            std::fs::read_to_string(&*GIT_ATTRIBUTES).unwrap()
        };
        let origin_git_attributes = read();

        // dir test
        add_crypt_attributes("target")?;
        dbg!(read());
        remove_crypt_attributes("target")?;
        assert_eq!(read().trim(), origin_git_attributes.trim());

        // file test
        add_crypt_attributes("LICENSE")?;
        dbg!(read());
        remove_crypt_attributes("LICENSE")?;
        assert_eq!(read().trim(), origin_git_attributes.trim());

        Ok(())
    }
}
