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
pub fn list_files(
    paths: impl IntoIterator<Item = impl AsRef<Path>>,
    cwd: impl AsRef<Path>,
) -> Vec<PathBuf> {
    let mut paths_iter = paths.into_iter();
    let cwd = cwd.as_ref();

    let mut builder = if let Some(first_path) = paths_iter.next() {
        debug_assert!(first_path.as_ref().is_relative());
        WalkBuilder::new(cwd.join(first_path))
    } else {
        return Vec::new();
    };

    for p in paths_iter {
        debug_assert!(p.as_ref().is_relative());
        builder.add(cwd.join(p));
    }

    builder
        .current_dir(cwd)
        .hidden(false)
        .git_ignore(true)
        .ignore(true)
        .git_global(true)
        .git_exclude(true)
        .follow_links(false)
        .threads(0);

    let parallel_walker: ignore::WalkParallel = builder.build_parallel();

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
    use path_absolutize::Absolutize as _;

    use super::*;

    #[test]
    fn test_list_files() {
        let paths = vec!["docs", ".gitignore", "src", "some_thing_not_exist"]
            .into_iter()
            .map(PathBuf::from);
        let res = list_files(paths, ".")
            .into_iter()
            .map(|x| x.absolutize().unwrap().to_path_buf())
            .collect::<Vec<_>>();
        dbg!(&res);
        assert!(
            res.contains(
                &Path::new("docs/README_zh-CN.md")
                    .absolutize()
                    .unwrap()
                    .to_path_buf()
            )
        );
        assert!(res.contains(&Path::new(".gitignore").absolutize().unwrap().to_path_buf()));
        assert!(
            res.contains(
                &Path::new("src/utils/mod.rs")
                    .absolutize()
                    .unwrap()
                    .to_path_buf()
            )
        );
        assert!(!res.contains(&Path::new("docs/").absolutize().unwrap().to_path_buf()));
    }

    #[test]
    fn test_cwd() {
        assert_eq!(
            list_files([".gitignore"], Path::new(".").absolutize().unwrap()),
            vec![Path::new(".gitignore").absolutize().unwrap()]
        );
        assert_eq!(
            list_files(["lib.rs"], Path::new("src").absolutize().unwrap()),
            vec![Path::new("src/lib.rs").absolutize().unwrap()]
        );
    }
}
