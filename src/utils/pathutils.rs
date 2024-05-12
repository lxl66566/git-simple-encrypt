use std::{
    io,
    path::{Path, PathBuf},
};

use tap::Tap;

#[allow(unused)]
pub trait FromBytes {
    fn from_bytes(b: &[u8]) -> Self;
}

impl FromBytes for PathBuf {
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
        self.as_ref().to_path_buf().tap_mut(|x| {
            #[cfg(target_family = "unix")]
            x.strip_prefix_better("./");
            #[cfg(target_family = "windows")]
            x.strip_prefix_better(".\\");
        })
    }
}

pub trait PathToAbsolute {
    fn absolute(&self) -> PathBuf;
}
impl<T: AsRef<Path>> PathToAbsolute for T {
    fn absolute(&self) -> PathBuf {
        std::path::absolute(self).unwrap_or_else(|e| {
            panic!(
                "Error in getting absolute path of `{:?}`: {e}",
                self.as_ref()
            )
        })
    }
}
