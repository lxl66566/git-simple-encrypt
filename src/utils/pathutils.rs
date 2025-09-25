use std::path::PathBuf;

use tap::Tap;

/// Append an extension to the path and return a new `PathBuf`.
pub trait PathAppendExt {
    fn append_ext(self, ext: &str) -> PathBuf;
}
impl PathAppendExt for PathBuf {
    fn append_ext(self, ext: &str) -> PathBuf {
        self.tap_mut(|p| p.as_mut_os_string().push(format!(".{ext}")))
    }
}
