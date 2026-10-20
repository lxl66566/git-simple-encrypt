//! Managed `.gitattributes` block for the clean/smudge filter integration.
//!
//! `install` (filter mode) exports one attribute line per crypt-list entry so
//! git runs our filters on exactly those paths. The block is delimited by
//! marker comments and regenerated in place, leaving user-managed lines
//! untouched. `refresh_gitattributes` reuses it whenever the crypt list
//! changes while filter mode is active; `uninstall` strips it again with
//! [`without_managed_block_bytes`].
//!
//! All content handling is byte-oriented: `.gitattributes` may legally hold
//! non-UTF-8 pattern bytes (raw path bytes under Unix), so files round-trip
//! through `&[u8]` and never fail — or get silently skipped — on encoding.

/// Filter driver name used in `.gitattributes` lines and git config keys.
pub const FILTER_NAME: &str = "git-se";

/// First line of the managed block.
const BEGIN_MARKER: &[u8] = b"# BEGIN git-simple-encrypt (managed)";
/// Last line of the managed block.
const END_MARKER: &[u8] = b"# END git-simple-encrypt";

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

/// First index of `needle` inside `haystack` (plain byte substring search).
///
/// The needles here are short ASCII markers over small files, so a naive
/// scan beats adding a substring-search dependency.
fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Whether `content` contains a managed block (i.e. filter integration was
/// installed here).
///
/// Generic over the content so `&str` callers (the pre-3.2 API) and
/// byte-oriented `&[u8]` callers compile unchanged.
#[must_use]
pub fn has_managed_block(content: impl AsRef<[u8]>) -> bool {
    find_sub(content.as_ref(), BEGIN_MARKER).is_some()
}

/// Byte range of the managed block in `content`: `(start, end)` where `end`
/// is exclusive, pointing just past the END-marker line's newline — or EOF
/// when the block is malformed (BEGIN without END).
fn managed_block_range(content: &[u8]) -> Option<(usize, usize)> {
    let start = find_sub(content, BEGIN_MARKER)?;
    let end = find_sub(&content[start..], END_MARKER).map_or(content.len(), |rel| {
        let marker_end = start + rel + END_MARKER.len();
        find_sub(&content[marker_end..], b"\n").map_or(content.len(), |nl| marker_end + nl + 1)
    });
    Some((start, end))
}

/// Assemble the managed block bytes: one attribute line per pattern.
fn managed_block(patterns: &[String]) -> Vec<u8> {
    let attrs = filter_attrs();
    let mut block = BEGIN_MARKER.to_vec();
    for pattern in patterns {
        block.push(b'\n');
        block.extend_from_slice(pattern.as_bytes());
        block.push(b' ');
        block.extend_from_slice(attrs.as_bytes());
    }
    block.push(b'\n');
    block.extend_from_slice(END_MARKER);
    block
}

/// Return `content` with the managed block replaced by one line per
/// `patterns` entry, appending the block at the end when none exists yet.
///
/// `patterns` are final lines written verbatim: callers pass *escaped*
/// patterns (see [`escape_pattern`]). Lines outside the block are preserved
/// byte-for-byte, non-UTF-8 content included.
#[must_use]
pub fn with_managed_block_bytes(content: &[u8], patterns: &[String]) -> Vec<u8> {
    let block = managed_block(patterns);

    let Some((start, end)) = managed_block_range(content) else {
        // Append a fresh block at the end.
        let mut out = Vec::with_capacity(content.len() + block.len() + 2);
        out.extend_from_slice(content);
        if !content.is_empty() {
            if !content.ends_with(b"\n") {
                out.push(b'\n');
            }
            // blank separator from user lines
            out.push(b'\n');
        }
        out.extend_from_slice(&block);
        out.push(b'\n');
        return out;
    };

    let mut out = Vec::with_capacity(content.len());
    out.extend_from_slice(&content[..start]);
    out.extend_from_slice(&block);
    out.push(b'\n');
    out.extend_from_slice(&content[end..]);
    out
}

/// Return `content` with the managed block stripped; unchanged when no
/// block exists.
///
/// The blank separator line [`with_managed_block_bytes`] adds before an
/// appended block is removed with it, so install → uninstall round-trips
/// the user's original file byte-for-byte. The result is empty when the
/// block was the only content; the caller decides whether to delete the
/// file.
#[must_use]
pub fn without_managed_block_bytes(content: &[u8]) -> Vec<u8> {
    let Some((start, end)) = managed_block_range(content) else {
        return content.to_vec();
    };
    // One byte of the "\n\n" separator before an appended block goes with
    // the block, keeping the user's own trailing blank line intact.
    let prefix_end = if content[..start].ends_with(b"\n\n") {
        start - 1
    } else {
        start
    };
    let mut out = Vec::with_capacity(prefix_end + (content.len() - end));
    out.extend_from_slice(&content[..prefix_end]);
    out.extend_from_slice(&content[end..]);
    out
}

/// Return `content` with the managed block replaced by one line per
/// `patterns` entry, appending the block at the end when none exists yet.
///
/// # Deprecated
///
/// Superseded by the byte-oriented [`with_managed_block_bytes`], which
/// round-trips the non-UTF-8 pattern lines `.gitattributes` legally holds.
/// This `&str` form remains for source compatibility with external callers
/// of the 3.1 API. The output is always valid UTF-8 — the input already is,
/// and the managed block only adds ASCII markers and UTF-8 rule lines — so
/// the lossy fallback below cannot trigger in practice.
#[deprecated(since = "3.2.0", note = "use `with_managed_block_bytes` instead")]
#[must_use]
pub fn with_managed_block(content: &str, patterns: &[String]) -> String {
    String::from_utf8(with_managed_block_bytes(content.as_bytes(), patterns))
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// Return `content` with the managed block stripped; unchanged when no
/// block exists.
///
/// # Deprecated
///
/// Superseded by the byte-oriented [`without_managed_block_bytes`], which
/// round-trips the non-UTF-8 pattern lines `.gitattributes` legally holds.
/// This `&str` form remains for source compatibility with external callers
/// of the 3.1 API; the output is UTF-8 for the same reason as
/// [`with_managed_block`]'s.
#[deprecated(since = "3.2.0", note = "use `without_managed_block_bytes` instead")]
#[must_use]
pub fn without_managed_block(content: &str) -> String {
    String::from_utf8(without_managed_block_bytes(content.as_bytes()))
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
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
    fn test_with_managed_block_bytes_appends() {
        // patterns are written verbatim (already escaped by the caller)
        let out = with_managed_block_bytes(b"", &pats(&["a.txt", "sub/**"]));
        assert_eq!(
            out,
            b"# BEGIN git-simple-encrypt (managed)\na.txt filter=git-se diff=git-se\nsub/** \
              filter=git-se diff=git-se\n# END git-simple-encrypt\n"
        );

        // user lines are preserved and separated by a blank line
        let out = with_managed_block_bytes(b"*.txt text\n", &pats(&["a.txt"]));
        assert_eq!(
            out,
            b"*.txt text\n\n# BEGIN git-simple-encrypt (managed)\na.txt filter=git-se \
              diff=git-se\n# END git-simple-encrypt\n"
        );

        // missing trailing newline in existing content is tolerated
        let out = with_managed_block_bytes(b"*.txt text", &pats(&["a.txt"]));
        assert!(out.starts_with(b"*.txt text\n\n# BEGIN"));
    }

    #[test]
    fn test_with_managed_block_bytes_replaces_in_place() {
        let old = b"keep me\n# BEGIN git-simple-encrypt (managed)\nold filter=git-se \
                   diff=git-se\n# END git-simple-encrypt\nkeep me too\n";
        let out = with_managed_block_bytes(old, &pats(&["new.txt"]));
        assert_eq!(
            out,
            b"keep me\n# BEGIN git-simple-encrypt (managed)\nnew.txt filter=git-se \
              diff=git-se\n# END git-simple-encrypt\nkeep me too\n"
        );

        // empty crypt list collapses the block but keeps the markers
        let out = with_managed_block_bytes(old, &[]);
        assert_eq!(
            out,
            b"keep me\n# BEGIN git-simple-encrypt (managed)\n# END git-simple-encrypt\nkeep \
               me too\n"
        );
        assert!(has_managed_block(&out));
        assert!(!has_managed_block(b"plain content"));
    }

    #[test]
    fn test_with_managed_block_bytes_malformed_missing_end() {
        // BEGIN without END: everything from BEGIN to EOF is replaced.
        let old = b"x\n# BEGIN git-simple-encrypt (managed)\nold line";
        let out = with_managed_block_bytes(old, &pats(&["a"]));
        assert_eq!(
            out,
            b"x\n# BEGIN git-simple-encrypt (managed)\na filter=git-se diff=git-se\n# END \
              git-simple-encrypt\n"
        );
    }

    #[test]
    fn test_without_managed_block_bytes() {
        // no block: unchanged
        assert_eq!(
            without_managed_block_bytes(b"*.txt text\n"),
            b"*.txt text\n"
        );
        assert_eq!(without_managed_block_bytes(b""), b"");

        // block in the middle: user lines around it are kept
        let full = b"keep\n\n# BEGIN git-simple-encrypt (managed)\na filter=git-se \
                     diff=git-se\n# END git-simple-encrypt\nmore\n";
        assert_eq!(without_managed_block_bytes(full), b"keep\nmore\n");

        // block only: empty result (caller deletes the file)
        let only = b"# BEGIN git-simple-encrypt (managed)\na filter=git-se diff=git-se\n# END \
                     git-simple-encrypt\n";
        assert_eq!(without_managed_block_bytes(only), b"");

        // malformed BEGIN without END: stripped to EOF
        let malformed = b"keep\n\n# BEGIN git-simple-encrypt (managed)\nold line";
        assert_eq!(without_managed_block_bytes(malformed), b"keep\n");
    }

    /// install → uninstall must round-trip the user's original
    /// `.gitattributes` byte-for-byte.
    ///
    /// The only tolerated delta: a file without a trailing newline (which
    /// install itself normalizes) comes back with one added.
    #[test]
    fn test_with_without_managed_block_bytes_roundtrip() {
        for original in [
            &b""[..],
            b"*.txt text\n".as_slice(),
            b"*.txt text".as_slice(),
            b"*.txt text\n\n".as_slice(),
            b"a binary\nb text\n".as_slice(),
        ] {
            let installed = with_managed_block_bytes(original, &pats(&["s.txt"]));
            let removed = without_managed_block_bytes(&installed);
            let mut with_newline = original.to_vec();
            with_newline.push(b'\n');
            assert!(
                removed == *original || removed == with_newline,
                "original {original:?} came back as {removed:?}"
            );
        }
    }

    /// Non-UTF-8 pattern lines are legal `.gitattributes` content (raw path
    /// bytes under Unix): appending, refreshing and stripping the managed
    /// block must round-trip them byte-for-byte.
    #[test]
    fn test_non_utf8_content_survives_managed_block_ops() {
        let original = b"*.bin text\n\xff\xfe raw \x80pattern\n";

        // install (append): raw line kept, block added after a blank line
        let installed = with_managed_block_bytes(original, &pats(&["a.txt"]));
        assert!(has_managed_block(&installed));
        assert!(installed.starts_with(original));
        assert!(installed.starts_with(b"*.bin text\n\xff\xfe raw \x80pattern\n\n# BEGIN"));

        // refresh (in-place replace): pattern lines swap, user lines stay
        let refreshed = with_managed_block_bytes(&installed, &pats(&["b.txt"]));
        assert!(refreshed.starts_with(original));
        assert!(find_sub(&refreshed, b"b.txt filter=git-se diff=git-se\n").is_some());
        assert!(find_sub(&refreshed, b"a.txt filter=git-se").is_none());

        // uninstall (strip): byte-identical to the original
        assert_eq!(without_managed_block_bytes(&refreshed), original);
    }

    /// The deprecated `&str` shims must produce exactly the byte API's
    /// output, and the generic `has_managed_block` must accept both `&str`
    /// and byte content.
    #[test]
    #[allow(deprecated)]
    fn test_deprecated_str_shims_match_byte_api() {
        let original = "*.txt text\n";
        let patterns = pats(&["a.txt"]);

        let installed = with_managed_block(original, &patterns);
        assert_eq!(
            installed.as_bytes(),
            with_managed_block_bytes(original.as_bytes(), &patterns)
        );
        // The generic predicate compiles for `&str` and byte content alike.
        assert!(!has_managed_block(original));
        assert!(has_managed_block(&installed));

        let removed = without_managed_block(&installed);
        assert_eq!(
            removed.as_bytes(),
            without_managed_block_bytes(installed.as_bytes())
        );
        // install → uninstall through the shims round-trips the original
        assert_eq!(removed, original);
    }
}
