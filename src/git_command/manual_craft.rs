//! This file contains some manual-written functions instead of git2_rs
//! bindings.
//! git2_rs reads and parse `.gitattributes` at every time in `check_attr`, and
//! its use of raw pointer has potential danger passed between multiple
//! threads.

use std::{
    io,
    path::Path,
    sync::{LazyLock as Lazy, RwLock},
};

use anyhow::anyhow;
use colored::Colorize;
use die_exit::DieWith;
use glob::Pattern;
use log::debug;

use super::{ATTR_NAME, GIT_ATTRIBUTES};
use crate::utils::{append_line_to_file, Git2Patch, PathToUnixStyle};

pub static GIT_ATTRIBUTES_PATTERNS: Lazy<RwLock<Vec<Pattern>>> = Lazy::new(|| {
    RwLock::new(
        read_gitattributes(GIT_ATTRIBUTES.as_path())
            .die_with(|e| format!("Read gitattributes error: {}", e)),
    )
});

fn read_gitattributes(path: impl AsRef<Path>) -> anyhow::Result<Vec<Pattern>> {
    let content = std::fs::read_to_string(path.as_ref())?;
    content
        .lines()
        .filter_map(|s| {
            let mut split = s.split_whitespace();
            let pattern = split.next();
            if let Some(attr) = split.next()
                && attr.starts_with(ATTR_NAME)
            {
                pattern
            } else {
                None
            }
        })
        .map(|s| Pattern::new(s).map_err(|e| anyhow!("Invalid pattern: {}", e)))
        .collect()
}

#[allow(dead_code)]
pub fn check_attr(path: impl AsRef<Path>) -> anyhow::Result<bool> {
    let path = path.as_ref().patch();
    debug!(
        "Checking attr for `{}`",
        format!("{}", path.to_string_lossy().green())
    );
    Ok(GIT_ATTRIBUTES_PATTERNS
        .read()
        .unwrap()
        .iter()
        .any(|pattern| pattern.matches(&path.to_string_lossy())))
}

pub fn add_attr(path: impl AsRef<Path>) -> io::Result<()> {
    let path = path.as_ref().to_unix_style();
    let mut content_to_write = path.to_string_lossy();
    content_to_write
        .to_mut()
        .push_str(&format!(" {}=1", ATTR_NAME));
    append_line_to_file(GIT_ATTRIBUTES.as_path(), &content_to_write)?;
    GIT_ATTRIBUTES_PATTERNS
        .write()
        .unwrap()
        .push(Pattern::new(&path.to_string_lossy()).unwrap());
    println!("Added attribute: {}", &content_to_write.green());
    Ok(())
}

pub fn remove_attr(path: &str) {
    let mut lock = GIT_ATTRIBUTES_PATTERNS.write().unwrap();
    if let Some(index) = lock.iter().position(|pattern| pattern.as_str() == path) {
        lock.remove(index);
    }
}

#[cfg(test)]
mod test_assets {
    use temp_testdir::TempDir;

    use super::*;

    #[test]
    fn test_read_gitattributes() {
        let temp_dir = TempDir::default();
        let path = temp_dir.join(".gitattributes");
        std::fs::write(
            path.as_path(),
            r#"
*.1 crypt=1
  123/** crypt=asdkjhf

123.3 something=else

"#,
        )
        .unwrap();
        let result = read_gitattributes(path.as_path()).unwrap();
        assert_eq!(result, ["*.1", "123/**"].map(|x| Pattern::new(x).unwrap()));
    }

    #[test]
    fn test_check_attr() {
        assert!(check_attr(Path::new("test_assets/test.txt")).unwrap());
        assert!(!check_attr(Path::new("test_assets")).unwrap());
    }
}
