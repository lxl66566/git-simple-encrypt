use std::path::{Path, PathBuf};

use tap::Tap;

pub trait PathFromBytes {
    fn from_bytes(b: &[u8]) -> Self;
}

impl PathFromBytes for PathBuf {
    #[cfg(unix)]
    fn from_bytes(b: &[u8]) -> Self {
        use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
        Self::from(OsStr::from_bytes(b))
    }
    #[cfg(windows)]
    fn from_bytes(b: &[u8]) -> Self {
        use std::str;
        Self::from(str::from_utf8(b).unwrap())
    }
}
pub trait PathAppendExt {
    fn append_ext(self, ext: &str) -> PathBuf;
}
impl PathAppendExt for PathBuf {
    fn append_ext(self, ext: &str) -> PathBuf {
        self.tap_mut(|p| p.as_mut_os_string().push(format!(".{ext}")))
    }
}
pub trait PathStripPrefix {
    fn strip_prefix_better(&mut self, prefix: impl AsRef<Path>) -> &mut Self;
}
impl PathStripPrefix for PathBuf {
    fn strip_prefix_better(&mut self, prefix: impl AsRef<Path>) -> &mut Self {
        if let Ok(res) = self.strip_prefix(prefix) {
            *self = res.to_path_buf();
        }
        self
    }
}
pub trait PathToUnixStyle {
    fn to_unix_style(&self) -> PathBuf;
}
impl<T: AsRef<Path>> PathToUnixStyle for T {
    fn to_unix_style(&self) -> PathBuf {
        self.as_ref().to_string_lossy().replace('\\', "/").into()
    }
}

/// tracking https://github.com/rust-lang/git2-rs/issues/1048
pub trait Git2Patch {
    fn patch(&self) -> PathBuf;
}
impl<T: AsRef<Path>> Git2Patch for T {
    fn patch(&self) -> PathBuf {
        self.as_ref()
            .to_path_buf()
            .tap_mut(|x| {
                x.strip_prefix_better("./");
            })
            .tap_mut(|x| {
                x.strip_prefix_better(".\\");
            })
    }
}
