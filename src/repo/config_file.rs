//! Repo-local config access.
//!
//! Secret values are written by editing the config file directly
//! (git-compatible escaping) so they never enter a child process argv; the
//! non-secret integration keys go through plain `git config` invocations.

use std::{path::PathBuf, process::Command};

use log::debug;

use super::{GIT_CONFIG_PREFIX, Repo};
use crate::{
    error::{Error, Result},
    utils::atomic_write,
};

impl Repo {
    /// Write a value to `<prefix>.<key>` in the repo-local git config.
    ///
    /// The value never appears in a subprocess argv (process listings would
    /// briefly expose it — this key holds a user password): the local config
    /// file is edited directly with git-compatible escaping, falling back to
    /// a plain `git config` invocation only when the file cannot be parsed
    /// confidently (see [`Repo::set_local_config_file`]).
    ///
    /// Note: the value is stored verbatim (no trimming); callers sanitize
    /// their input themselves. Both key-setting paths trim before calling
    /// this — the interactive `p` prompt (inside `prompt_password`) and the
    /// deprecated `set key` — so they agree on the stored key, while inner
    /// whitespace always survives.
    pub fn set_config(&self, key: &str, value: &str) -> Result<()> {
        let temp = String::from(GIT_CONFIG_PREFIX) + key;
        if let Err(e) = self.set_local_config_file(&temp, value) {
            debug!("direct config-file write failed ({e}); falling back to `git config` argv");
            return self.run(&["config", "--local", &temp, value]);
        }
        Ok(())
    }

    /// Set `section.var = value` by editing the repo-local config file
    /// directly, keeping the value out of every child process.
    ///
    /// `git config` has no stdin mode for writes (there is no `--stdin`
    /// option for it up to git 2.50), and an argv value is briefly visible
    /// in process listings. The value is escaped exactly the way git's own
    /// config writer does ([`escape_config_value`]), so the result is
    /// byte-compatible with git-written values and reads back identically
    /// (newlines, quotes, tabs, leading/trailing spaces, non-ASCII).
    fn set_local_config_file(&self, full_key: &str, value: &str) -> Result<()> {
        let Some((section, var)) = split_config_key(full_key) else {
            return Err(Error::Other(format!(
                "unsupported config key for file write: {full_key}"
            )));
        };
        let path = self.local_config_file()?;
        let content = match std::fs::read_to_string(&path) {
            Ok(content) => content,
            // A missing file is the fresh-repo case: start from empty.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            // Any other failure (encoding, permissions) must NOT be masked:
            // rewriting from an empty misread would clobber the user's config.
            Err(e) => return Err(e.into()),
        };
        let updated = set_config_line(&content, section, var, &escape_config_value(value));
        atomic_write(&path, updated.as_bytes())
    }

    /// Absolute path of the repo-local config file (the `git config --local`
    /// target). `--git-path config` resolves linked-worktree pointers to the
    /// shared config — the same file `--local` writes — and may return a
    /// repo-root-relative path.
    fn local_config_file(&self) -> Result<PathBuf> {
        let out = self.run_with_output(&["rev-parse", "--git-path", "config"])?;
        let path = PathBuf::from(out.trim());
        Ok(if path.is_absolute() {
            path
        } else {
            self.path.join(path)
        })
    }

    /// Write to an unprefixed git config key (e.g. `filter.git-se.clean`) in
    /// the repo-local git config. Unlike [`Repo::set_config`], no namespace is
    /// prepended — used for the git integration settings git itself reads.
    /// These values are not secrets, so the plain argv form is fine.
    pub fn set_raw_config(&self, key: &str, value: &str) -> Result<()> {
        self.run(&["config", "--local", key, value])
    }

    /// Remove an unprefixed repo-local git config key written by
    /// [`Repo::set_raw_config`]. A missing key is not an error: uninstall
    /// must stay idempotent across repeated or partial installs.
    pub(super) fn unset_raw_config(&self, key: &str) -> Result<()> {
        let out = Command::new("git")
            .current_dir(&self.path)
            .args(["config", "--local", "--unset", key])
            .output()?;
        // Exit code 5 = the key did not exist; anything else is a real
        // failure. Git drops the section header once its last key is gone.
        if !out.status.success() && out.status.code() != Some(5) {
            return Err(Error::Git(
                String::from_utf8_lossy(&out.stderr).into_owned(),
            ));
        }
        Ok(())
    }

    /// Read an unprefixed key from the repo-local git config only (no
    /// global/system lookup, matching [`Repo::set_raw_config`]).
    ///
    /// The value is read with `-z` (NUL-terminated) so its exact bytes
    /// survive; trimming the LF of plain output would corrupt values that
    /// legitimately end in whitespace.
    pub fn get_raw_config(&self, key: &str) -> Result<String> {
        self.run_with_output_bytes(&["config", "--local", "--get", "-z", key])
            .map(|out| {
                // `--get` emits at most one record; cut at the first NUL
                // defensively anyway.
                let end = out.iter().position(|&b| b == 0).unwrap_or(out.len());
                String::from_utf8_lossy(&out[..end]).into_owned()
            })
    }

    /// Read `<prefix>.<key>` from the repo-local git config only.
    ///
    /// `--local` matches [`Repo::set_config`]: a stray key in the user's
    /// global/system config must not be silently adopted — it would surface
    /// as inexplicable decrypt failures in new repositories instead of a
    /// clear "key not set" error.
    pub fn get_config(&self, key: &str) -> Result<String> {
        let temp = String::from(GIT_CONFIG_PREFIX) + key;
        self.get_raw_config(&temp)
    }
}

/// Split `section.var` for the plain (non-subsection) section syntax used
/// by all git-se keys.
///
/// Splits at the FIRST dot: a second dot would denote a
/// `[section "subsection"]` key, which this writer does not support.
fn split_config_key(key: &str) -> Option<(&str, &str)> {
    let (section, var) = key.split_once('.')?;
    (!section.is_empty() && !var.is_empty() && !var.contains('.')).then_some((section, var))
}

/// Escape a config value in git's double-quoted syntax, mirroring what
/// `git config` itself writes.
///
/// `\`, `"`, LF and TAB become their backslash escapes; every other byte
/// (CR and non-ASCII included) stays raw inside the quotes, exactly how git
/// serializes such values.
fn escape_config_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Whether a trimmed line is the plain section header `[section]`
/// (case-insensitive; a subsection form `[section "x"]` is a different key
/// namespace and never matches; a trailing comment is tolerated).
fn is_plain_section(trimmed: &str, section: &str) -> bool {
    trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.split(']').next())
        .is_some_and(|name| name.trim().eq_ignore_ascii_case(section))
}

/// Whether a trimmed line assigns `var` (case-insensitive name, `=` with
/// optional spaces; comment lines never match because their pre-`=` text
/// contains the `#`/`;` marker).
fn is_var_assignment(trimmed: &str, var: &str) -> bool {
    trimmed
        .find('=')
        .is_some_and(|eq| trimmed[..eq].trim().eq_ignore_ascii_case(var))
}

/// Replace or insert `var = escaped_value` inside `[section]` of a config
/// file body, appending a fresh section when absent.
///
/// Line-oriented and conservative: existing lines outside the touched entry
/// are preserved verbatim.
fn set_config_line(content: &str, section: &str, var: &str, escaped_value: &str) -> String {
    let entry = format!("\t{var} = {escaped_value}");
    // split('\n') (not lines()) keeps any \r attached to line bodies, so a
    // CRLF file is not silently normalized; the trailing "" element
    // represents the final newline.
    let mut lines: Vec<String> = content.split('\n').map(str::to_string).collect();

    // Pass 1: an existing assignment of `var` inside the section?
    let mut in_section = false;
    let mut existing = None;
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_section = is_plain_section(trimmed, section);
        } else if in_section && existing.is_none() && is_var_assignment(trimmed, var) {
            existing = Some(i);
        }
    }

    match existing {
        Some(i) => lines[i] = entry,
        None => {
            if let Some(header) = lines
                .iter()
                .position(|l| is_plain_section(l.trim(), section))
            {
                // Insert right below the section header.
                lines.insert(header + 1, entry);
            } else {
                lines.push(format!("[{section}]"));
                lines.push(entry);
            }
        },
    }
    let mut out = lines.join("\n");
    // Config files are newline-terminated; appending after a body without a
    // trailing newline (or to an empty one) must not break that.
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use path_absolutize::Absolutize;

    use super::*;
    use crate::repo::init_temp_repo;

    #[test]
    fn test_set_get_config_roundtrip() -> Result<()> {
        let dir = init_temp_repo();
        let repo_path = dir.path().absolutize().unwrap().to_path_buf();
        let repo = Repo::open(&repo_path)?;

        repo.set_config("key", "hunter2")?;
        let read_back = repo.get_config("key")?;
        assert_eq!(read_back, "hunter2");
        Ok(())
    }

    /// Passwords are config values too: every byte spelling that can come
    /// out of a terminal or argv must survive a write→read cycle untouched.
    ///
    /// This locks both the direct-file escaping and the `-z` exact read
    /// (a trimming read used to corrupt leading/trailing whitespace).
    #[test]
    fn test_set_get_config_special_value_roundtrip() -> Result<()> {
        let dir = init_temp_repo();
        let repo_path = dir.path().absolutize().unwrap().to_path_buf();
        let repo = Repo::open(&repo_path)?;

        let values = [
            "with space",
            "  padded  ",
            "a\"b\\c",
            "tab\there",
            "line1\nline2",
            "crlf\r\nend",
            "密码🔐パス",
            "#comment ;semi",
            "",
        ];
        for value in values {
            repo.set_config("key", value)?;
            assert_eq!(
                repo.get_config("key")?,
                value,
                "roundtrip failed for {value:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_config_line_surgery() {
        // replace within existing section
        let base = "[core]\n\tbare = false\n[git-simple-encrypt]\n\tkey = \"old\"\n";
        assert_eq!(
            set_config_line(base, "git-simple-encrypt", "key", "\"new\""),
            "[core]\n\tbare = false\n[git-simple-encrypt]\n\tkey = \"new\"\n"
        );
        // insert into an existing section that lacks the var
        assert_eq!(
            set_config_line(base, "git-simple-encrypt", "other", "1"),
            "[core]\n\tbare = false\n[git-simple-encrypt]\n\tother = 1\n\tkey = \"old\"\n"
        );
        // append a missing section
        assert_eq!(
            set_config_line("[core]\n\tbare = false\n", "git-se", "k", "v"),
            "[core]\n\tbare = false\n\n[git-se]\n\tk = v\n"
        );
        // case-insensitive section/var matching, subsections never match
        let mixed = "[Git-Simple-Encrypt]\nKEY = x\n[git-simple-encrypt \"sub\"]\n\tkey = y\n";
        assert_eq!(
            set_config_line(mixed, "git-simple-encrypt", "key", "\"z\""),
            "[Git-Simple-Encrypt]\n\tkey = \"z\"\n[git-simple-encrypt \"sub\"]\n\tkey = y\n"
        );
        // empty body
        assert_eq!(set_config_line("", "s", "v", "1"), "\n[s]\n\tv = 1\n");
    }
}
