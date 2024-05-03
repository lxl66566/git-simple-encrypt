mod binding;

use crate::cli::CLI;
use crate::crypt::{decrypt_file, encrypt_file, ENCRYPTED_EXTENSION};
use crate::utils::{append_line_to_file, bytes2path, AppendExt, END_OF_LINE};
use anyhow::Ok;
pub use binding::{add_all, need_crypt, set_key, KEY, REPO};
use colored::Colorize;
use die_exit::{die, Die};
use futures_util::stream::FuturesOrdered;
use futures_util::StreamExt;
use regex::Regex;
use std::path::{Path, PathBuf};
use std::sync::LazyLock as Lazy;

const KEY_NAME: &str = "simple-git-encrypt.key";
const ATTR_NAME: &str = "crypt";
static GIT_ATTRIBUTES: Lazy<PathBuf> = Lazy::new(|| CLI.repo.join(".gitattributes"));

pub async fn encrypt_repo() -> anyhow::Result<()> {
    add_all()?;
    let lock = REPO.lock().unwrap().index()?;
    let mut encrypt_futures = lock
        .iter()
        .map(|x| CLI.repo.join(bytes2path(&x.path)))
        .filter(|x| x.is_file())
        .filter_map(|x| need_crypt(x).ok().flatten())
        .map(encrypt_file)
        .collect::<FuturesOrdered<_>>();
    while let Some(ret) = encrypt_futures.next().await {
        ret.unwrap_or_else(|err| {
            eprintln!(
                "{}",
                format!("warning: failed to encrypt file: {}", err).yellow()
            )
        });
    }
    add_all()?;
    Ok(())
}

pub async fn decrypt_repo() -> anyhow::Result<()> {
    let lock = REPO.lock().unwrap().index()?;
    let mut decrypt_futures = lock
        .iter()
        .map(|x| CLI.repo.join(bytes2path(&x.path)))
        .filter(|x| x.extension().unwrap_or_default() == ENCRYPTED_EXTENSION)
        .filter(|x| x.is_file())
        .filter_map(|x| {
            need_crypt(x.with_extension(""))
                .ok()
                .flatten()
                .map(|x| x.append_ext())
        })
        .map(decrypt_file)
        .collect::<FuturesOrdered<_>>();
    while let Some(ret) = decrypt_futures.next().await {
        ret.unwrap_or_else(|err| {
            eprintln!(
                "{}",
                format!("warning: failed to decrypt file: {}", err).yellow()
            )
        });
    }
    Ok(())
}

/// add file/folder to .gitattributes, means it needs encrypt.
pub fn add_crypt_attributes(path: impl AsRef<Path>) -> anyhow::Result<()> {
    let mut test_path = path.as_ref().to_owned();
    if test_path.is_dir() {
        test_path.push("any");
    }
    if need_crypt(test_path)?.is_some() {
        println!("`{:?}` is already marked as encrypt-needed.", path.as_ref());
        #[cfg(not(test))]
        std::process::exit(0);
        #[cfg(test)]
        anyhow::bail!("`{:?}` is already marked as encrypt-needed.", path.as_ref());
    }
    let mut path = path.as_ref().to_path_buf();
    if path.is_dir() {
        path.push("**");
    }
    let mut content_to_write = path.to_str().die("Invalid path.").replace('\\', "/");
    content_to_write.push_str(&format!(" {}=1", ATTR_NAME));
    append_line_to_file(GIT_ATTRIBUTES.as_path(), &content_to_write)?;
    debug_assert!(need_crypt(path)?.is_some());
    println!("Added attribute: {}", &content_to_write.green());
    Ok(())
}

pub fn remove_crypt_attributes(path: impl AsRef<Path>) -> anyhow::Result<()> {
    let mut test_path = path.as_ref().to_path_buf();
    if test_path.is_dir() {
        test_path.push("any");
    }
    if need_crypt(test_path)?.is_none() {
        println!("`{:?}` is not marked as encrypt-needed.", path.as_ref());
        #[cfg(not(test))]
        std::process::exit(0);
        #[cfg(test)]
        anyhow::bail!("`{:?}` is not marked as encrypt-needed.", path.as_ref());
    }
    let content = std::fs::read_to_string(GIT_ATTRIBUTES.as_path())?;
    let mut content_vec: Vec<&str> = content.split('\n').collect();
    let re = Regex::new(&format!(
        r#"^(./)?{}(/\*\*)?\s"#,
        path.as_ref()
            .to_str()
            .die("Invalid path.")
            .replace('\\', "/"),
    ))
    .expect("builtin regex should be valid.");
    let index = content_vec.iter().position(|line| re.is_match(line));
    let removed_attr: &str;
    if let Some(i) = index {
        removed_attr = content_vec.remove(i);
    } else {
        die!("Cannot find the match attribute. You can delete this attribute by editing `.gitattributes`.")
    }
    content_vec.pop_if(|line| line.trim().is_empty());
    std::fs::write(GIT_ATTRIBUTES.as_path(), content_vec.join(END_OF_LINE))?;
    debug_assert!(need_crypt(path.as_ref().to_owned())?.is_none());
    println!("Removed attribute: `{}`", removed_attr.red());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_remove_attr() -> anyhow::Result<()> {
        let read = || {
            // sleep, otherwise the read() access will be denied. (git2_rs call has delay)
            std::thread::sleep(std::time::Duration::from_millis(20));
            std::fs::read_to_string(".gitattributes").unwrap()
        };
        let origin_git_attributes = read();

        // dir test
        add_crypt_attributes("tests")?;
        dbg!(read());
        remove_crypt_attributes("tests")?;
        assert_eq!(read().trim(), origin_git_attributes.trim());

        // file test
        add_crypt_attributes("LICENSE")?;
        dbg!(read());
        remove_crypt_attributes("LICENSE")?;
        assert_eq!(read().trim(), origin_git_attributes.trim());

        Ok(())
    }
}
