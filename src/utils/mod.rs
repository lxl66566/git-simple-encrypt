use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::mpsc,
};

use anyhow::Result;
use assert2::assert;
use ignore::{WalkBuilder, WalkState};

/// Format a byte array into a hex string
#[allow(dead_code)]
#[cfg(any(test, debug_assertions))]
pub fn format_hex(value: &[u8]) -> String {
    use std::fmt::Write;
    value.iter().fold(String::new(), |mut output, b| {
        let _ = write!(output, "{b:02x}");
        output
    })
}

/// Prompt the user for a password
pub fn prompt_password(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut password = String::new();
    std::io::stdin().read_line(&mut password)?;
    assert!(!password.is_empty(), "Password must not be empty");
    Ok(password.trim().to_string())
}

/// If the given path is a file, return the file name. Otherwise, return the
/// recursive file name in the given dir.
pub fn list_files(paths: impl IntoIterator<Item = impl AsRef<Path>>) -> Vec<PathBuf> {
    let mut paths_iter = paths.into_iter();

    let Some(first_path) = paths_iter.next() else {
        return Vec::new();
    };

    let mut builder = WalkBuilder::new(first_path);

    for p in paths_iter {
        builder.add(p);
    }

    builder
        .hidden(false)
        .git_ignore(true)
        .ignore(true)
        .git_global(true)
        .git_exclude(true)
        .follow_links(false)
        .threads(0);

    let parallel_walker = builder.build_parallel();

    let (tx, rx) = mpsc::channel();

    parallel_walker.run(|| {
        let tx = tx.clone();
        Box::new(move |result| {
            if let Ok(entry) = result
                && let Some(file_type) = entry.file_type()
                && file_type.is_file()
            {
                let _ = tx.send(entry.into_path());
            }
            WalkState::Continue
        })
    });

    drop(tx);
    rx.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    #[test]
    fn test_list_files() {
        let paths = vec!["docs", ".gitignore", "src", "some_thing_not_exist"]
            .into_iter()
            .map(PathBuf::from);
        let res = list_files(paths);
        dbg!(&res);
        assert!(res.contains(&PathBuf::from("docs/README_zh-CN.md")));
        assert!(res.contains(&PathBuf::from(".gitignore")));
        assert!(res.contains(&PathBuf::from("src/utils/mod.rs")));
        assert!(!res.contains(&PathBuf::from("docs/")));
    }
}
