//! Outcome aggregation for encrypt/decrypt reports.
//!
//! Per-file listings do not scale to repo-wide runs (thousands of files),
//! so reports aggregate outcomes per parent directory and cap the listing:
//! the output volume stays constant no matter the run size. [`ReportMode::Verbose`]
//! switches to the full per-file list for run-by-run auditing.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use pathdiff::diff_paths;

use crate::utils::style::Colorize;

/// Maximum paths listed individually before the summary report collapses
/// the rest into one line.
const REPORT_LIST_LIMIT: usize = 10;

/// Directories shown inline in the one-line session summary.
const INLINE_DIR_LIMIT: usize = 3;

/// Outcome of one file passing through an encrypt or decrypt operation.
///
/// Failures are not a variant: batch runs carry them in
/// `BatchSummary::errors` (full context) and filter sessions count them via
/// [`DirReport::record_failure`]; the report layer only renders paths it
/// can attribute to a completed outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOutcome {
    /// Content was rewritten (encrypted or decrypted).
    Transformed,
    /// Left untouched: already-encrypted input on encrypt, non-encrypted
    /// input on decrypt — the idempotent passthrough of both the manual
    /// commands and the git filters.
    PassedThrough,
}

/// Which operation a report describes; carries the label/past-participle
/// pair so callers cannot hand in arbitrary strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportAction {
    Encrypt,
    Decrypt,
}

impl ReportAction {
    /// Headline form ("Encrypt complete: ...").
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Encrypt => "Encrypt",
            Self::Decrypt => "Decrypt",
        }
    }

    /// Per-file and inline-summary form ("42 encrypted").
    #[must_use]
    pub const fn past(self) -> &'static str {
        match self {
            Self::Encrypt => "encrypted",
            Self::Decrypt => "decrypted",
        }
    }
}

/// Verbosity of the result report printed by the manual `e`/`d` commands.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ReportMode {
    /// Directory-level summary with a capped listing.
    #[default]
    Summary,
    /// Every file listed individually, without truncation.
    Verbose,
}

impl From<bool> for ReportMode {
    fn from(verbose: bool) -> Self {
        if verbose { Self::Verbose } else { Self::Summary }
    }
}

/// Per-file outcomes of one run or filter session, aggregated on render.
#[derive(Debug, Default)]
pub struct DirReport {
    /// One entry per processed file; a path may appear more than once
    /// within a filter session (git can send the same pathname repeatedly).
    files: Vec<(PathBuf, FileOutcome)>,
    /// Failures, counted without paths: their detail travels through
    /// `BatchSummary::errors` / the filter's per-file error log instead.
    failed: usize,
}

impl DirReport {
    /// Record the outcome of one file.
    pub fn record(&mut self, path: &Path, outcome: FileOutcome) {
        self.files.push((path.to_path_buf(), outcome));
    }

    /// Record one failure (count only; detail is reported elsewhere).
    pub const fn record_failure(&mut self) {
        self.failed += 1;
    }

    /// Record `count` failures at once (count only; detail is reported
    /// elsewhere).
    pub const fn record_failures(&mut self, count: usize) {
        self.failed += count;
    }

    /// Whether anything at all was recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.files.is_empty() && self.failed == 0
    }

    fn tally(&self, outcome: FileOutcome) -> usize {
        self.files.iter().filter(|(_, o)| *o == outcome).count()
    }

    /// Repo-relative display names of the transformed files, aggregated by
    /// parent directory; files directly under the root stay individual
    /// entries. Sorted by count descending, then by name.
    fn dir_entries(&self, root: &Path) -> Vec<(String, usize)> {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for (path, outcome) in &self.files {
            if *outcome != FileOutcome::Transformed {
                continue;
            }
            let rel = relative_display(path, root);
            let parent = Path::new(&rel)
                .parent()
                .and_then(Path::to_str)
                .unwrap_or("");
            // An empty parent means the file sits directly under the root:
            // it stays an individual entry instead of joining a "" bucket.
            let entry = if parent.is_empty() { rel } else { format!("{parent}/") };
            *counts.entry(entry).or_default() += 1;
        }
        let mut entries: Vec<_> = counts.into_iter().collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        entries
    }

    /// "Encrypt complete: 3 succeeded, 1 passed through" (+ failures when
    /// present).
    fn tally_line(&self, action: ReportAction) -> String {
        let label = format!("{} complete", action.label()).bold();
        let head = format!(
            "{}: {} succeeded, {} passed through",
            label,
            self.tally(FileOutcome::Transformed).to_string().green(),
            self.tally(FileOutcome::PassedThrough).to_string().yellow(),
        );
        if self.failed > 0 {
            format!(
                "{head}, {} {}",
                self.failed.to_string().red(),
                "failed".red()
            )
        } else {
            head
        }
    }

    /// Multi-line summary: tally line plus a directory listing capped at
    /// [`REPORT_LIST_LIMIT`] paths.
    fn render_summary(&self, action: ReportAction, root: &Path) -> String {
        use std::fmt::Write as _;

        let mut out = format!("\n{}", self.tally_line(action));
        let entries = self.dir_entries(root);
        if entries.is_empty() {
            return out;
        }

        let shown = &entries[..entries.len().min(REPORT_LIST_LIMIT)];
        let width = shown.iter().map(|(name, _)| name.len()).max().unwrap_or(0);
        for (name, count) in shown {
            let _ = write!(out, "\n  {name:<width$}  {count}");
        }
        if entries.len() > REPORT_LIST_LIMIT {
            let rest = &entries[REPORT_LIST_LIMIT..];
            let files: usize = rest.iter().map(|(_, c)| c).sum();
            let _ = write!(
                out,
                "\n  {}",
                format!("... and {} more paths ({} files)", rest.len(), files).dimmed()
            );
        }
        out
    }

    /// Full per-file listing grouped by outcome, sorted, no truncation.
    fn render_verbose(&self, action: ReportAction, root: &Path) -> String {
        use std::fmt::Write as _;

        let mut out = format!("\n{}", self.tally_line(action));
        for (title, outcome) in [
            (format!("{}:", action.past()), FileOutcome::Transformed),
            ("passed through:".to_string(), FileOutcome::PassedThrough),
        ] {
            let mut paths: Vec<String> = self
                .files
                .iter()
                .filter(|(_, o)| *o == outcome)
                .map(|(p, _)| relative_display(p, root))
                .collect();
            if paths.is_empty() {
                continue;
            }
            paths.sort();
            let _ = write!(out, "\n  {title}");
            for path in paths {
                let _ = write!(out, "\n    {path}");
            }
        }
        out
    }

    /// Compact one-line tally with the top directories inline, e.g.
    /// `42 encrypted, 3 passed through (secrets/ 39, config/ 3)`.
    #[must_use]
    pub fn inline(&self, action: ReportAction, root: &Path) -> String {
        let mut parts = vec![format!(
            "{} {}",
            self.tally(FileOutcome::Transformed),
            action.past()
        )];
        let passed = self.tally(FileOutcome::PassedThrough);
        if passed > 0 {
            parts.push(format!("{passed} passed through"));
        }
        if self.failed > 0 {
            parts.push(format!("{} failed", self.failed));
        }
        let mut line = parts.join(", ");

        let dirs = self.dir_entries(root);
        if !dirs.is_empty() {
            use std::fmt::Write as _;

            let shown: Vec<String> = dirs[..dirs.len().min(INLINE_DIR_LIMIT)]
                .iter()
                .map(|(name, count)| format!("{name} {count}"))
                .collect();
            let overflow = dirs.len().saturating_sub(INLINE_DIR_LIMIT);
            if overflow > 0 {
                let _ = write!(line, " ({}, +{overflow} more)", shown.join(", "));
            } else {
                let _ = write!(line, " ({})", shown.join(", "));
            }
        }
        line
    }

    /// Print the result report on stdout in the requested verbosity.
    pub fn print(&self, action: ReportAction, root: &Path, mode: ReportMode) {
        let body = match mode {
            ReportMode::Summary => self.render_summary(action, root),
            ReportMode::Verbose => self.render_verbose(action, root),
        };
        println!("{body}");
    }
}

/// Repo-relative display string: absolute paths are rebased on `root`
/// (falling back to the path itself when it is not under `root`), relative
/// paths (git filter pathnames) pass through unchanged.
fn relative_display(path: &Path, root: &Path) -> String {
    let rel = if path.is_absolute() {
        diff_paths(path, root).unwrap_or_else(|| path.to_path_buf())
    } else {
        path.to_path_buf()
    };
    rel.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filled(paths: &[(&str, FileOutcome)]) -> DirReport {
        let mut report = DirReport::default();
        for (path, outcome) in paths {
            report.record(Path::new(path), *outcome);
        }
        report
    }

    #[test]
    fn test_dir_entries_aggregate_sort_and_root_files() {
        let report = filled(&[
            ("secrets/a.txt", FileOutcome::Transformed),
            ("secrets/b.txt", FileOutcome::Transformed),
            ("secrets/sub/c.txt", FileOutcome::Transformed),
            ("config/env.yaml", FileOutcome::Transformed),
            ("key.md", FileOutcome::Transformed),
            ("secrets/skip.txt", FileOutcome::PassedThrough),
        ]);
        // Passed-through files stay out of the directory listing; the tie
        // between `key.md` and `secrets/sub/` breaks by name.
        let root = Path::new("");
        assert_eq!(report.dir_entries(root), vec![
            ("secrets/".to_string(), 2),
            ("config/".to_string(), 1),
            ("key.md".to_string(), 1),
            ("secrets/sub/".to_string(), 1),
        ]);
    }

    #[test]
    fn test_summary_collapses_beyond_limit() {
        let names: Vec<String> = (0..15).map(|i| format!("d{i:02}/f.txt")).collect();
        let paths: Vec<(&str, FileOutcome)> = names
            .iter()
            .map(|n| (n.as_str(), FileOutcome::Transformed))
            .collect();
        let report = filled(&paths);
        let text = report.render_summary(ReportAction::Encrypt, Path::new(""));

        assert!(text.contains("Encrypt complete: 15 succeeded, 0 passed through"));
        assert!(text.contains("d00/"));
        assert!(text.contains("... and 5 more paths (5 files)"));
        assert!(!text.contains("d14/"));
    }

    #[test]
    fn test_tally_line_counts_failures() {
        let mut report = filled(&[("a.txt", FileOutcome::Transformed)]);
        report.record_failure();
        report.record_failure();
        let text = report.render_summary(ReportAction::Decrypt, Path::new(""));
        assert!(text.contains("1 succeeded, 0 passed through, 2 failed"));
    }

    #[test]
    fn test_verbose_lists_every_file_sorted() {
        let report = filled(&[
            ("b.txt", FileOutcome::Transformed),
            ("a.txt", FileOutcome::Transformed),
            ("c.txt", FileOutcome::PassedThrough),
        ]);
        let text = report.render_verbose(ReportAction::Encrypt, Path::new(""));
        let a = text.find("a.txt").expect("a.txt listed");
        let b = text.find("b.txt").expect("b.txt listed");
        let section = text.rfind("passed through:").expect("section header");
        assert!(
            a < b && b < section,
            "transformed files sorted, section last"
        );
        assert!(text.contains("encrypted:"));
    }

    #[test]
    fn test_inline_format_and_overflow() {
        let mut paths: Vec<(&str, FileOutcome)> = vec![
            ("secrets/a", FileOutcome::Transformed),
            ("secrets/b", FileOutcome::Transformed),
            ("secrets/c", FileOutcome::Transformed),
            ("config/d", FileOutcome::Transformed),
            ("config/e", FileOutcome::Transformed),
            ("docs/f", FileOutcome::Transformed),
        ];
        // 5 distinct dirs → inline overflow form.
        paths.push(("g", FileOutcome::Transformed));
        paths.push(("h", FileOutcome::Transformed));
        let report = filled(&paths);

        let line = report.inline(ReportAction::Encrypt, Path::new(""));
        assert!(line.starts_with("8 encrypted ("));
        assert!(line.contains("secrets/ 3"));
        assert!(line.contains("+2 more"));
        assert!(!line.contains("passed through"), "zero count omitted");
    }

    #[test]
    fn test_inline_passed_through_and_empty() {
        let report = filled(&[
            ("a", FileOutcome::Transformed),
            ("b", FileOutcome::PassedThrough),
            ("c", FileOutcome::PassedThrough),
        ]);
        assert_eq!(
            report.inline(ReportAction::Decrypt, Path::new("")),
            "1 decrypted, 2 passed through (a 1)"
        );
        assert!(DirReport::default().is_empty());
    }
}
