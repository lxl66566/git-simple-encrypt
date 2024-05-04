//! This file contains some manual-written functions instead of git2_rs
//! bindings.
//! git2_rs reads and parse `.gitattributes` at every time in `check_attr`, and
//! its use of raw pointer has potential danger passed between multiple
//! threads.

use std::{path::Path, sync::LazyLock as Lazy};

use anyhow::anyhow;
use die_exit::DieWith;
use glob::Pattern;

use super::{binding::Git2Patch, ATTR_NAME, GIT_ATTRIBUTES};
use crate::utils::ToUnixStyle;

pub static GIT_ATTRIBUTES_PATTERNS: Lazy<Vec<Pattern>> = Lazy::new(|| {
    read_gitattributes(GIT_ATTRIBUTES.as_path())
        .die_with(|e| format!("Read gitattributes error: {}", e))
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
    Ok(GIT_ATTRIBUTES_PATTERNS
        .iter()
        .any(|pattern| dbg!(pattern).matches(dbg!(&path.to_string_lossy()))))
}

#[cfg(test)]
mod tests {
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
        assert!(check_attr(Path::new("tests/test.txt")).unwrap());
        assert!(!check_attr(Path::new("tests")).unwrap());
    }
}
