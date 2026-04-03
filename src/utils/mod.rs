use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::mpsc,
};

use anyhow::{Context, Result};
use assert2::assert;
use colored::Colorize;
use ignore::{WalkBuilder, WalkState};
use indicatif::{ProgressBar, ProgressStyle};

use crate::crypt::{HEADER_LEN, MAGIC, VERSION};

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

// --- Reporting & Progress Helpers ---

/// Maximum number of files to display individually before collapsing.
const REPORT_LIST_LIMIT: usize = 20;

/// Print a pre-operation report listing the target files and total count.
/// If the list exceeds `REPORT_LIST_LIMIT`, show the first few and summarize
/// the rest as "... and N more files".
pub fn print_pre_report(action: &str, files: &[PathBuf], repo_path: &Path) {
    let count = files.len();
    println!(
        "\n{} {} {}",
        action.bold(),
        format!("({count} files)").cyan(),
        ":".dimmed()
    );

    for f in &files[..count.min(REPORT_LIST_LIMIT)] {
        let relative = pathdiff::diff_paths(f, repo_path).unwrap_or_else(|| f.clone());
        println!("  {}", relative.display());
    }

    if count > REPORT_LIST_LIMIT {
        let remaining = count - REPORT_LIST_LIMIT;
        println!("  {}", format!("... and {remaining} more files").dimmed());
    }
    println!();
}

/// Print a post-operation summary report.
pub fn print_post_report(action: &str, total: usize, skipped: usize, failed: usize) {
    let succeeded = total - skipped - failed;
    let label = format!("{action} complete").bold();

    if failed > 0 {
        println!(
            "\n{}: {} succeeded, {} skipped, {} {}",
            label,
            succeeded.to_string().green(),
            skipped.to_string().yellow(),
            failed.to_string().red(),
            "failed".red(),
        );
    } else {
        println!(
            "\n{}: {} succeeded, {} skipped",
            label,
            succeeded.to_string().green(),
            skipped.to_string().yellow(),
        );
    }
}

/// Create a styled progress bar for encryption/decryption/checking.
pub fn create_progress_bar(len: usize, prefix: &'static str) -> ProgressBar {
    let pb = ProgressBar::new(len as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{prefix:.bold} {bar:40.cyan/blue} {pos}/{len} {spinner} [{elapsed_precise}]",
        )
        .unwrap()
        .progress_chars("#>-"),
    );
    pb.set_prefix(prefix);
    pb.enable_steady_tick(std::time::Duration::from_millis(200));
    pb
}

/// Check whether a single file has a valid GITSE encrypted header.
/// Returns an error if the file cannot be read (IO error).
pub fn is_file_encrypted(path: &Path) -> Result<bool> {
    let mut file = fs::File::open(path).with_context(|| {
        format!(
            "Failed to open file for encryption check: {}",
            path.display()
        )
    })?;
    let mut header_bytes = [0u8; HEADER_LEN];
    let bytes_read = file.read(&mut header_bytes)?;
    if bytes_read < HEADER_LEN {
        // File is smaller than the header, definitely not encrypted
        return Ok(false);
    }
    Ok(&header_bytes[0..5] == MAGIC && header_bytes[5] == VERSION)
}

/// Resolve the target file list for the repo. If `paths` is empty, use the
/// crypt list from the config; otherwise, use the given paths.
pub fn resolve_target_files(
    paths: &[PathBuf],
    crypt_list: &[String],
    repo_path: &Path,
) -> Vec<PathBuf> {
    if paths.is_empty() {
        list_files(crypt_list.iter(), repo_path)
    } else {
        list_files(paths, repo_path)
    }
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
