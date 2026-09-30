pub(crate) mod parallel;
mod progress;
pub(crate) mod style;

use std::{
    collections::HashSet,
    ffi::OsStr,
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
    sync::mpsc,
};

use ignore::{WalkBuilder, WalkState};
use log::warn;
use path_absolutize::Absolutize as _;
use pathdiff::diff_paths;
pub use progress::Progress;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use crate::{
    crypt::{is_encrypted_header, read_header_bytes},
    error::{Error, Result},
    utils::style::Colorize,
};

/// Format a byte array into a hex string
#[allow(dead_code)]
#[cfg(any(test, debug_assertions))]
#[must_use]
pub fn format_hex(value: &[u8]) -> String {
    use std::fmt::Write;
    value.iter().fold(String::new(), |mut output, b| {
        let _ = write!(output, "{b:02x}");
        output
    })
}

/// Atomically write `data` to `path` by writing to a temp file first, then
/// renaming. This prevents partial writes from corrupting the target file.
///
/// The temp file is fsynced before the rename, so a power loss leaves either
/// the old or the new content — never a truncated file. On Unix, an existing
/// target's mode is carried over and fresh files get the conventional 0644;
/// without this every rewritten file would inherit the temp file's 0600.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp_file = NamedTempFile::new_in(parent)?;
    temp_file.write_all(data)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path).map_or(0o644, |m| m.permissions().mode());
        std::fs::set_permissions(temp_file.path(), std::fs::Permissions::from_mode(mode))?;
    }

    temp_file.as_file().sync_all()?;
    temp_file
        .persist(path)
        .map_err(|e| Error::AtomicPersist(path.to_path_buf(), e.to_string()))?;
    Ok(())
}

/// Prompt the user for a password.
///
/// On a real terminal the input is read with echo disabled (rpassword) so
/// the plaintext never lands in the terminal scrollback. Non-TTY stdin
/// (pipes, CI, `echo pw | git-se p`) falls back to the plain line read:
/// there is no echo to suppress there, and scripted workflows depend on it.
///
/// Returns an empty-password error if the user enters only whitespace. The
/// returned string is wrapped in [`Zeroizing`] so the plaintext is scrubbed
/// from memory on drop.
pub fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
    use std::io::IsTerminal;

    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut password = String::new();
    if std::io::stdin().is_terminal() {
        password = rpassword::read_password()?;
        // rpassword consumes the Enter key silently; keep the visual line.
        println!();
    } else {
        std::io::stdin().read_line(&mut password)?;
    }
    let trimmed = password.trim();
    if trimmed.is_empty() {
        return Err(Error::EmptyPassword);
    }
    // Scrub the raw input buffer too.
    let result = Zeroizing::new(trimmed.to_string());
    zeroize::Zeroize::zeroize(&mut password);
    Ok(result)
}

/// Where a user-supplied path falls relative to the repository root.
///
/// Component-based, so `/` and `\` separators parse identically on Windows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathRelativeTo {
    /// Strictly inside the repository; the payload is the repo-relative path.
    Inside(PathBuf),
    /// The repository root itself (e.g. `.` or the root path).
    Root,
    /// Outside the repository: an absolute path elsewhere, or a relative
    /// path with a leading `..` component. The payload is the offending
    /// path in its most readable form.
    Outside(PathBuf),
}

/// Resolve a user-supplied `path` against `repo_root`.
///
/// `repo_root` should be absolute; escape detection (`..`) is only sound
/// with an absolute anchor (`Repo` paths and the CLI parser guarantee it).
/// Purely lexical: `.`/`..` components are normalized (via
/// [`Absolutize::absolutize_from`]) without touching the filesystem, and
/// symlinks are not resolved — matching the walker's `follow_links(false)`.
/// A symlink pointing outside the repo therefore still reports
/// [`PathRelativeTo::Inside`]; rejecting those is a possible future policy
/// layered on top of this function.
#[must_use]
pub fn path_relative_to(path: &Path, repo_root: &Path) -> PathRelativeTo {
    let absolute = path.absolutize_from(repo_root);
    // A different root component (e.g. another drive on Windows) can never
    // be expressed relative to the repo, and `diff_paths` silently mangles
    // such pairs into a path without a leading `..` — reject them up front.
    if absolute.is_absolute()
        && repo_root.is_absolute()
        && absolute.components().next() != repo_root.components().next()
    {
        return PathRelativeTo::Outside(absolute.into_owned());
    }
    diff_paths(absolute.as_ref(), repo_root).map_or_else(
        // Unexpressible relation (e.g. mixed absolute/relative inputs).
        || PathRelativeTo::Outside(absolute.into_owned()),
        |relative| match relative.components().next() {
            // diff_paths yields an empty path only when both sides are equal.
            None => PathRelativeTo::Root,
            Some(Component::ParentDir) => PathRelativeTo::Outside(relative),
            Some(_) => PathRelativeTo::Inside(relative),
        },
    )
}

/// Whether `path` equals `ancestor` or lies underneath it.
/// Both sides must already be normalized (no `.`/`..` components).
fn is_within(ancestor: &Path, path: &Path) -> bool {
    let mut ancestor = ancestor.components();
    let mut path = path.components();
    loop {
        match (ancestor.next(), path.next()) {
            // Ancestor exhausted: it is an ancestor-or-equal of `path`.
            (None, _) => return true,
            (Some(a), Some(b)) if a == b => {},
            // `path` exhausted first, or the components diverge.
            (Some(_), _) => return false,
        }
    }
}

/// Whether any component of `path` is exactly `.git`.
///
/// Covers the git metadata directory at any depth, including a walk root
/// placed inside one. Only the exact component matches, so look-alikes such
/// as `.gitignore` or `.!git` are unaffected. Encrypting anything under
/// `.git` bricks the repository and its recovery path alike (the password
/// lives in `.git/config`).
pub(crate) fn has_git_component(path: &Path) -> bool {
    path.components()
        .any(|c| c.as_os_str() == OsStr::new(".git"))
}

/// If the given path is a file, return the file name. Otherwise, return the
/// recursive file name in the given dir.
///
/// Paths may be relative (resolved against `cwd`) or absolute; paths
/// resolving outside `cwd` are skipped with a warning — the walker must
/// never touch files outside the repository.
pub fn list_files(
    paths: impl IntoIterator<Item = impl AsRef<Path>>,
    cwd: impl AsRef<Path>,
) -> Vec<PathBuf> {
    let cwd = cwd.as_ref();
    let roots: Vec<PathBuf> = paths
        .into_iter()
        .filter_map(|path| repo_walk_root(path.as_ref(), cwd))
        .collect();
    walk_files(&roots, cwd, true)
}

/// Resolve one user-supplied path into a walker root under `repo_root`;
/// `None` (after a warning) for paths that escape it.
fn repo_walk_root(path: &Path, repo_root: &Path) -> Option<PathBuf> {
    match path_relative_to(path, repo_root) {
        PathRelativeTo::Inside(relative) => Some(repo_root.join(relative)),
        PathRelativeTo::Root => Some(repo_root.to_path_buf()),
        PathRelativeTo::Outside(offending) => {
            warn!(
                "skipping {}: the path is outside the repository and will not be touched",
                offending.display()
            );
            None
        },
    }
}

/// Join a repo-relative path (possibly empty, meaning the root itself)
/// back onto `repo_root` without relying on `join("")` semantics.
fn join_repo_relative(repo_root: &Path, relative: &Path) -> PathBuf {
    if relative.as_os_str().is_empty() {
        repo_root.to_path_buf()
    } else {
        repo_root.join(relative)
    }
}

/// Collect all regular files under `roots` (recursively for directories).
///
/// Entries with a `.git` path component are always skipped, regardless of
/// the ignore setting. When `apply_ignore` is false, gitignore-style
/// filtering is disabled — used by [`ignored_in_crypt_entries`] to detect
/// files the crypt list promised to cover but the walker silently excluded.
fn walk_files(roots: &[PathBuf], cwd: &Path, apply_ignore: bool) -> Vec<PathBuf> {
    let Some((first, rest)) = roots.split_first() else {
        return Vec::new();
    };
    let mut builder = WalkBuilder::new(first);
    for root in rest {
        builder.add(root);
    }

    builder
        .current_dir(cwd)
        .hidden(false)
        .git_ignore(apply_ignore)
        .ignore(apply_ignore)
        .git_global(apply_ignore)
        .git_exclude(apply_ignore)
        .follow_links(false)
        .threads(0);

    let parallel_walker: ignore::WalkParallel = builder.build_parallel();

    let (tx, rx) = mpsc::channel();

    parallel_walker.run(|| {
        let tx = tx.clone();
        Box::new(move |result| {
            if let Ok(entry) = result {
                if has_git_component(entry.path()) {
                    // Refuse to emit anything from `.git` and do not descend.
                    return WalkState::Skip;
                }
                if let Some(file_type) = entry.file_type()
                    && file_type.is_file()
                {
                    let _ = tx.send(entry.into_path());
                }
            }
            WalkState::Continue
        })
    });

    drop(tx);
    let mut files: Vec<PathBuf> = rx.into_iter().collect();
    // Parallel walking yields a non-deterministic order and may emit the same
    // file twice when roots overlap (e.g. both `dir` and `dir/file.txt`).
    // Sorting + dedup keeps the output stable; cost is negligible (ms-level
    // even for tens of thousands of entries).
    files.sort();
    files.dedup();
    files
}

/// Normalize crypt-list entries (stored as repo-relative strings) into
/// relative paths.
///
/// Entries escaping the repo are dropped with a warning — only reachable
/// via a hand-edited config, since `add` rejects them.
fn normalized_crypt_entries(crypt_list: &[String], repo_path: &Path) -> Vec<PathBuf> {
    crypt_list
        .iter()
        .filter_map(|entry| {
            match path_relative_to(Path::new(entry), repo_path) {
                PathRelativeTo::Inside(relative) => Some(relative),
                // The repo root itself (e.g. a legacy empty entry written by
                // `add .` before it was rejected): keep walking the whole
                // repo; the walker's `.git` filter keeps git metadata safe.
                PathRelativeTo::Root => Some(PathBuf::new()),
                PathRelativeTo::Outside(_) => {
                    warn!("skipping crypt list entry outside the repository: {entry}");
                    None
                },
            }
        })
        .collect()
}

/// Files excluded by ignore rules from crypt-list coverage.
///
/// Re-walks the covered roots with ignore filtering disabled and diffs
/// against `found` (the ignore-aware walk result). The remainder are files
/// the crypt list promises to encrypt but the walker silently excluded —
/// both `e` and the `check` pre-commit defense would skip them unnoticed.
///
/// Only directory roots are re-walked: an explicit file root bypasses the
/// ignore rules anyway, so it cannot hide anything.
fn ignored_in_crypt_entries(
    covered_roots: &[PathBuf],
    repo_path: &Path,
    found: &[PathBuf],
) -> Vec<PathBuf> {
    let dir_roots: Vec<PathBuf> = covered_roots
        .iter()
        .filter(|root| root.is_dir())
        .cloned()
        .collect();
    if dir_roots.is_empty() {
        return Vec::new();
    }
    let unfiltered = walk_files(&dir_roots, repo_path, false);
    let found_set: HashSet<&Path> = found.iter().map(PathBuf::as_path).collect();
    let mut missed: Vec<PathBuf> = unfiltered
        .into_iter()
        .filter(|path| !found_set.contains(path.as_path()))
        .collect();
    missed.sort();
    missed
}

/// Warn about files the crypt list covers but the ignore rules exclude.
///
/// Printed on stdout (visible in the `e`/`check` report flow) and mirrored
/// to the log: these files stay plaintext and `check` cannot see them
/// either, so without this warning they form a silent hole in the
/// pre-commit line of defense.
fn warn_ignored_in_crypt_entries(ignored: &[PathBuf], repo_path: &Path) {
    if ignored.is_empty() {
        return;
    }
    let listed = ignored
        .iter()
        .map(|path| {
            diff_paths(path, repo_path)
                .unwrap_or_else(|| path.clone())
                .display()
                .to_string()
        })
        .collect::<Vec<_>>()
        .join(", ");
    warn!(
        "{} file(s) inside crypt-list entries are excluded by ignore rules and will not be \
         encrypted or checked: {listed}",
        ignored.len()
    );
    println!(
        "\n{} {} file(s) inside crypt-list entries are excluded by ignore rules and will NOT be \
         encrypted or checked:",
        "Warning:".yellow().bold(),
        ignored.len()
    );
    for path in ignored {
        let relative = diff_paths(path, repo_path).unwrap_or_else(|| path.clone());
        println!("  - {}", relative.display());
    }
}

// --- Reporting & Progress Helpers ---

/// Maximum number of files to display individually before collapsing.
const REPORT_LIST_LIMIT: usize = 10;

/// Print a pre-operation report listing the target files and total count.
/// If the list exceeds `REPORT_LIST_LIMIT`, show the first few and summarize
/// the rest as "... and N more files".
pub fn print_pre_report(action: &str, files: &[impl AsRef<Path>], repo_path: &Path) {
    let count = files.len();
    println!(
        "\n{} {} {}",
        action.bold(),
        format!("({count} files)").cyan(),
        ":".dimmed()
    );

    for f in &files[..count.min(REPORT_LIST_LIMIT)] {
        let relative =
            diff_paths(f.as_ref(), repo_path).unwrap_or_else(|| f.as_ref().to_path_buf());
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

/// Check whether a single file has a valid GITSE encrypted header.
/// Returns an error if the file cannot be read (IO error).
pub fn is_file_encrypted(path: &Path) -> Result<bool> {
    let mut file = fs::File::open(path)?;
    // Shared sniff helper: a file shorter than the header cannot be
    // encrypted (Ok(None)); real IO errors propagate.
    Ok(read_header_bytes(&mut file)?.is_some_and(|bytes| is_encrypted_header(&bytes)))
}

/// Resolve the target file list for the repo. If `paths` is empty, use the
/// crypt list from the config; otherwise, use the given paths.
///
/// Paths resolving outside the repo are skipped with a warning. Files that
/// ignore rules exclude from crypt-list coverage are reported explicitly:
/// directory scans outside the crypt list keep plain ignore semantics, but
/// inside crypt entries a silently skipped file would be a silent hole in
/// the pre-commit line of defense.
#[must_use]
pub fn resolve_target_files(
    paths: &[PathBuf],
    crypt_list: &[String],
    repo_path: &Path,
) -> Vec<PathBuf> {
    let crypt_entries = normalized_crypt_entries(crypt_list, repo_path);

    let (roots, covered_roots): (Vec<PathBuf>, Vec<PathBuf>) = if paths.is_empty() {
        // List mode: every crypt entry is covered by definition.
        let roots: Vec<PathBuf> = crypt_entries
            .iter()
            .map(|relative| join_repo_relative(repo_path, relative))
            .collect();
        let covered = roots.clone();
        (roots, covered)
    } else {
        let mut roots = Vec::with_capacity(paths.len());
        let mut covered = Vec::new();
        for path in paths {
            match path_relative_to(path, repo_path) {
                PathRelativeTo::Inside(relative) => {
                    roots.push(repo_path.join(&relative));
                    // Only roots inside crypt-list coverage get the
                    // ignored-file warning; scans elsewhere keep plain
                    // ignore semantics with no extra pass.
                    if crypt_entries
                        .iter()
                        .any(|entry| is_within(entry, &relative))
                    {
                        covered.push(join_repo_relative(repo_path, &relative));
                    }
                },
                PathRelativeTo::Root => {
                    roots.push(repo_path.to_path_buf());
                    // The whole repo is walked; crypt coverage decides the
                    // warning.
                    covered.extend(
                        crypt_entries
                            .iter()
                            .map(|relative| join_repo_relative(repo_path, relative)),
                    );
                },
                PathRelativeTo::Outside(offending) => {
                    warn!(
                        "skipping {}: the path is outside the repository and will not be touched",
                        offending.display()
                    );
                },
            }
        }
        (roots, covered)
    };

    let files = walk_files(&roots, repo_path, true);
    let ignored = ignored_in_crypt_entries(&covered_roots, repo_path, &files);
    warn_ignored_in_crypt_entries(&ignored, repo_path);
    files
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use tempfile::TempDir;

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

    #[test]
    fn test_list_files_overlapping_roots_dedup_and_sorted() {
        let temp_dir = TempDir::new().unwrap();
        let base = temp_dir.path();
        let dir = base.join("dir");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("a.txt"), "a").unwrap();
        fs::write(dir.join("b.txt"), "b").unwrap();

        // Overlapping roots: `dir` (walked recursively, covers dir/a.txt)
        // plus `dir/a.txt` itself. Constructed directly because the `add`
        // command now deduplicates identical paths at the config level.
        let res = list_files(["dir", "dir/a.txt"], base);
        assert_eq!(res, vec![dir.join("a.txt"), dir.join("b.txt")]);
    }

    #[test]
    fn test_list_files_skips_git_components() {
        let temp_dir = TempDir::new().unwrap();
        let base = temp_dir.path();
        fs::create_dir_all(base.join(".git").join("objects")).unwrap();
        fs::write(base.join(".git").join("HEAD"), "ref").unwrap();
        fs::write(base.join(".git").join("objects").join("x"), "o").unwrap();
        // A nested repository's .git must be skipped as well.
        fs::create_dir_all(base.join("sub").join(".git")).unwrap();
        fs::write(base.join("sub").join(".git").join("HEAD"), "ref").unwrap();
        // Look-alike names are NOT .git components.
        fs::write(base.join(".!git"), "lookalike").unwrap();
        fs::write(base.join(".gitignore"), "ig").unwrap();
        fs::write(base.join("normal.txt"), "n").unwrap();

        let res = list_files(["."], base);
        assert_eq!(res, vec![
            base.join(".!git"),
            base.join(".gitignore"),
            base.join("normal.txt"),
        ]);
    }

    #[test]
    fn test_list_files_accepts_absolute_paths() {
        // Absolute inputs must go through the same normalization as relative
        // ones (they used to hit a debug-only panic).
        let temp_dir = TempDir::new().unwrap();
        let base = temp_dir.path();
        fs::write(base.join("a.txt"), "a").unwrap();
        let res = list_files([base.join("a.txt")], base);
        assert_eq!(res, vec![base.join("a.txt")]);

        // Absolute path outside the walk root: skipped (warned), not walked.
        let outside = TempDir::new().unwrap();
        fs::write(outside.path().join("b.txt"), "b").unwrap();
        let res = list_files([outside.path().join("b.txt")], base);
        assert!(res.is_empty());
    }

    #[test]
    fn test_path_relative_to() {
        let root = if cfg!(windows) {
            PathBuf::from("C:\\repo")
        } else {
            PathBuf::from("/repo")
        };
        let outside = if cfg!(windows) {
            PathBuf::from("D:\\elsewhere")
        } else {
            PathBuf::from("/elsewhere")
        };

        assert_eq!(
            path_relative_to(Path::new("dir/x"), &root),
            PathRelativeTo::Inside(PathBuf::from("dir").join("x"))
        );
        // `.`/`..` are normalized lexically.
        assert_eq!(
            path_relative_to(Path::new("./x"), &root),
            PathRelativeTo::Inside(PathBuf::from("x"))
        );
        assert_eq!(
            path_relative_to(Path::new("dir/../x"), &root),
            PathRelativeTo::Inside(PathBuf::from("x"))
        );
        assert_eq!(
            path_relative_to(Path::new("."), &root),
            PathRelativeTo::Root
        );
        assert_eq!(path_relative_to(&root, &root), PathRelativeTo::Root);
        assert_eq!(
            path_relative_to(&root.join("x"), &root),
            PathRelativeTo::Inside(PathBuf::from("x"))
        );
        assert_eq!(
            path_relative_to(Path::new("../outside"), &root),
            PathRelativeTo::Outside(PathBuf::from("..").join("outside"))
        );
        assert_eq!(
            path_relative_to(Path::new(".."), &root),
            PathRelativeTo::Outside(PathBuf::from(".."))
        );
        assert_eq!(
            path_relative_to(&outside, &root),
            PathRelativeTo::Outside(outside.clone())
        );

        // The backslash escape variant must parse as ParentDir on Windows
        // (on Unix `..\outside` is one literal component, i.e. inside).
        if cfg!(windows) {
            assert_eq!(
                path_relative_to(Path::new("..\\outside"), &root),
                PathRelativeTo::Outside(PathBuf::from("..").join("outside"))
            );
        }
    }

    #[test]
    fn test_is_within() {
        let p = |s: &str| PathBuf::from(s);
        assert!(is_within(&p("dir"), &p("dir")));
        assert!(is_within(&p("dir"), &p("dir/sub/x")));
        assert!(!is_within(&p("dir"), &p("dirx")));
        assert!(!is_within(&p("dir/sub"), &p("dir")));
        // The empty path is the repo root: everything is within it.
        assert!(is_within(&PathBuf::new(), &p("anything/x")));
    }

    #[test]
    fn test_ignored_in_crypt_entries_detects_ignored_files() {
        let temp_dir = TempDir::new().unwrap();
        let base = temp_dir.path();
        // The ignore crate only applies .gitignore rules when a `.git`
        // entry exists somewhere up the chain (require_git default).
        fs::create_dir_all(base.join(".git")).unwrap();
        let dir = base.join("dir");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("keep.txt"), "keep").unwrap();
        fs::write(dir.join("x.env"), "ignored").unwrap();
        fs::write(base.join(".gitignore"), "*.env\n").unwrap();

        let found = list_files(["dir"], base);
        assert_eq!(found, vec![dir.join("keep.txt")]);

        let missed = ignored_in_crypt_entries(std::slice::from_ref(&dir), base, &found);
        assert_eq!(missed, vec![dir.join("x.env")]);
    }
}
