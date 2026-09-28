//! Managed `.gitattributes` block for the clean/smudge filter integration.
//!
//! `install` (filter mode) exports one attribute line per crypt-list entry so
//! git runs our filters on exactly those paths. The block is delimited by
//! marker comments and regenerated in place, leaving user-managed lines
//! untouched. `refresh_gitattributes` reuses it whenever the crypt list
//! changes while filter mode is active.

/// Filter driver name used in `.gitattributes` lines and git config keys.
pub const FILTER_NAME: &str = "git-se";

/// First line of the managed block.
const BEGIN_MARKER: &str = "# BEGIN git-simple-encrypt (managed)";
/// Last line of the managed block.
const END_MARKER: &str = "# END git-simple-encrypt";

/// Attributes assigned to every managed pattern.
#[must_use]
pub fn filter_attrs() -> String {
    format!("filter={FILTER_NAME} diff={FILTER_NAME}")
}

/// Escape a literal path into a verbatim gitignore-style pattern.
///
/// The raw glob `suffix` (`""` for files, `"/**"` for directory cascade) is
/// appended after escaping; it must stay inside the quotes when the
/// pattern itself needs quoting.
#[must_use]
pub fn escape_pattern(pattern: &str, suffix: &str) -> String {
    // A bare pattern token ends at the first whitespace (middle spaces
    // cannot be backslash-escaped in .gitattributes), so patterns with
    // whitespace or `"` must be C-style quoted.
    if pattern.chars().any(|c| c.is_whitespace() || c == '"') {
        quote_pattern(pattern, suffix)
    } else {
        let mut out = escape_bare(pattern);
        out.push_str(suffix);
        out
    }
}

/// Bare (unquoted) escaping. Backslash escapes are honored by git's
/// wildmatch; escaping a non-special character is harmless.
fn escape_bare(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    for c in pattern.chars() {
        if matches!(c, '\\' | '*' | '?' | '[' | ']') {
            out.push('\\');
        }
        out.push(c);
    }
    // A leading `#` starts a comment and a leading `!` is rejected by git;
    // backslash-escaping makes both literal.
    if out.starts_with('#') || out.starts_with('!') {
        out.insert(0, '\\');
    }
    out
}

/// C-quoted escaping for patterns containing whitespace or `"`.
///
/// Limitation: git rejects quoted patterns starting with `!` (no valid
/// escape exists); such a path cannot be matched in .gitattributes.
fn quote_pattern(pattern: &str, suffix: &str) -> String {
    let mut out = String::with_capacity(pattern.len() + suffix.len() + 2);
    out.push('"');
    for c in pattern.chars() {
        match c {
            // `\*` is not a valid C escape and makes git drop the whole
            // line; single-char classes escape glob metacharacters inside
            // quotes instead. `]` is already literal outside a class.
            '*' => out.push_str("[*]"),
            '?' => out.push_str("[?]"),
            '[' => out.push_str("[[]"),
            '"' => out.push_str("\\\""),
            // C-unquote consumes one backslash layer, wildmatch the next.
            '\\' => out.push_str("\\\\\\\\"),
            c => out.push(c),
        }
    }
    out.push_str(suffix);
    out.push('"');
    out
}

/// Whether `content` contains a managed block (i.e. filter integration was
/// installed here).
#[must_use]
pub fn has_managed_block(content: &str) -> bool {
    content.contains(BEGIN_MARKER)
}

/// Return `content` with the managed block replaced by one line per
/// `patterns` entry, appending the block at the end when none exists yet.
///
/// `patterns` are final lines written verbatim: callers pass *escaped*
/// patterns (see [`escape_pattern`]).
#[must_use]
pub fn with_managed_block(content: &str, patterns: &[String]) -> String {
    let mut block = String::from(BEGIN_MARKER);
    for pattern in patterns {
        block.push('\n');
        block.push_str(pattern);
        block.push(' ');
        block.push_str(&filter_attrs());
    }
    block.push('\n');
    block.push_str(END_MARKER);

    let Some(start) = content.find(BEGIN_MARKER) else {
        // Append a fresh block at the end.
        let mut out = String::with_capacity(content.len() + block.len() + 2);
        out.push_str(content);
        if !content.is_empty() {
            if !content.ends_with('\n') {
                out.push('\n');
            }
            // blank separator from user lines
            out.push('\n');
        }
        out.push_str(&block);
        out.push('\n');
        return out;
    };

    // Replace the existing block in place. `block_end` is the end of the
    // END-marker line (exclusive), or EOF when the block is malformed.
    let block_end = content[start..]
        .find(END_MARKER)
        .map_or(content.len(), |rel| {
            let marker_end = start + rel + END_MARKER.len();
            content[marker_end..]
                .find('\n')
                .map_or(content.len(), |nl| marker_end + nl + 1)
        });

    let mut out = String::with_capacity(content.len());
    out.push_str(&content[..start]);
    out.push_str(&block);
    out.push('\n');
    out.push_str(&content[block_end..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pats(items: &[&str]) -> Vec<String> {
        items.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn test_escape_pattern() {
        assert_eq!(escape_pattern("dir/file.txt", ""), "dir/file.txt");
        assert_eq!(escape_pattern("a*b", ""), "a\\*b");
        assert_eq!(escape_pattern("a?b", ""), "a\\?b");
        assert_eq!(escape_pattern("a[b", ""), "a\\[b");
        assert_eq!(escape_pattern("a\\b", ""), "a\\\\b");
        assert_eq!(escape_pattern("#hash", ""), "\\#hash");
        assert_eq!(escape_pattern("!bang", ""), "\\!bang");
        // directory cascade: raw glob suffix appended after escaping
        assert_eq!(escape_pattern("sub", "/**"), "sub/**");
        assert_eq!(escape_pattern("a*b", "/**"), "a\\*b/**");
    }

    #[test]
    fn test_escape_pattern_quoted() {
        // whitespace forces C-style quoting; glob chars use char classes
        // because `\*` is an invalid C escape
        assert_eq!(escape_pattern("a b.txt", ""), "\"a b.txt\"");
        assert_eq!(escape_pattern("trail ", ""), "\"trail \"");
        assert_eq!(escape_pattern("a *b.txt", ""), "\"a [*]b.txt\"");
        assert_eq!(escape_pattern("a ?.txt", ""), "\"a [?].txt\"");
        assert_eq!(escape_pattern("a [b].txt", ""), "\"a [[]b].txt\"");
        assert_eq!(escape_pattern("with\"q.txt", ""), "\"with\\\"q.txt\"");
        // the glob suffix stays inside the quotes
        assert_eq!(escape_pattern("my dir", "/**"), "\"my dir/**\"");
        // a leading `#` needs no escape inside quotes
        assert_eq!(escape_pattern("#hash dir", ""), "\"#hash dir\"");
    }

    #[test]
    fn test_with_managed_block_appends() {
        // patterns are written verbatim (already escaped by the caller)
        let out = with_managed_block("", &pats(&["a.txt", "sub/**"]));
        assert_eq!(
            out,
            "# BEGIN git-simple-encrypt (managed)\na.txt filter=git-se diff=git-se\nsub/** \
             filter=git-se diff=git-se\n# END git-simple-encrypt\n"
        );

        // user lines are preserved and separated by a blank line
        let out = with_managed_block("*.txt text\n", &pats(&["a.txt"]));
        assert_eq!(
            out,
            "*.txt text\n\n# BEGIN git-simple-encrypt (managed)\na.txt filter=git-se \
             diff=git-se\n# END git-simple-encrypt\n"
        );

        // missing trailing newline in existing content is tolerated
        let out = with_managed_block("*.txt text", &pats(&["a.txt"]));
        assert!(out.starts_with("*.txt text\n\n# BEGIN"));
    }

    #[test]
    fn test_with_managed_block_replaces_in_place() {
        let old = "keep me\n# BEGIN git-simple-encrypt (managed)\nold filter=git-se \
                   diff=git-se\n# END git-simple-encrypt\nkeep me too\n";
        let out = with_managed_block(old, &pats(&["new.txt"]));
        assert_eq!(
            out,
            "keep me\n# BEGIN git-simple-encrypt (managed)\nnew.txt filter=git-se diff=git-se\n# \
             END git-simple-encrypt\nkeep me too\n"
        );

        // empty crypt list collapses the block but keeps the markers
        let out = with_managed_block(old, &[]);
        assert_eq!(
            out,
            "keep me\n# BEGIN git-simple-encrypt (managed)\n# END git-simple-encrypt\nkeep me \
             too\n"
        );
        assert!(has_managed_block(&out));
        assert!(!has_managed_block("plain content"));
    }

    #[test]
    fn test_with_managed_block_malformed_missing_end() {
        // BEGIN without END: everything from BEGIN to EOF is replaced.
        let old = "x\n# BEGIN git-simple-encrypt (managed)\nold line";
        let out = with_managed_block(old, &pats(&["a"]));
        assert_eq!(
            out,
            "x\n# BEGIN git-simple-encrypt (managed)\na filter=git-se diff=git-se\n# END \
             git-simple-encrypt\n"
        );
    }
}
