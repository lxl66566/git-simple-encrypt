use crate::cli::CLI;
use crate::crypt::{decrypt_file, encrypt_file, ENCRYPTED_EXTENSION};
use crate::utils::{append_line_to_file, bytes2path, AppendExt, END_OF_LINE};
use anyhow::Ok;
use colored::Colorize;
use die_exit::{die, Die, DieWith};
use futures_util::future::join_all;
use git2::{AttrCheckFlags, IndexAddOption, Repository};
use log::debug;
use regex::Regex;
use std::path::{Path, PathBuf};
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
static GIT_ATTRIBUTES: Lazy<PathBuf> = Lazy::new(|| CLI.repo.join(".gitattributes"));

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
pub static KEY: Lazy<String> = Lazy::new(|| "123".into());

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
            eprintln!(
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
            eprintln!(
                "{}",
                format!("warning: failed to decrypt file: {}", err).yellow()
            )
        }
    });
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
    let mut removed_attr = None;
    if let Some(i) = index {
        removed_attr = Some(content_vec.remove(i));
    } else {
        die!("Cannot find the match attribute. You can delete this attribute by editing `.gitattributes`.")
    }
    std::fs::write(GIT_ATTRIBUTES.as_path(), content_vec.join(END_OF_LINE))?;
    debug_assert!(need_crypt(path.as_ref().to_owned())?.is_none());
    println!("Removed attribute: `{}`", removed_attr.unwrap().red());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[compio::test]
    async fn test_need_crypt() {
        let file = PathBuf::from(".").join("tests/test.txt");
        std::assert!(need_crypt(file.clone()).unwrap().is_some());
    }

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
