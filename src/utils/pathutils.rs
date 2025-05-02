use std::path::{Path, PathBuf};

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

/// Append an extension to the path and return a new `PathBuf`.
pub trait PathAppendExt {
    fn append_ext(self, ext: &str) -> PathBuf;
}
impl PathAppendExt for PathBuf {
    fn append_ext(self, ext: &str) -> PathBuf {
        self.tap_mut(|p| p.as_mut_os_string().push(format!(".{ext}")))
    }
}

/// tracking <https://github.com/rust-lang/git2-rs/issues/1048>
#[allow(unused)]
pub trait Git2Patch {
    /// remove prefix "./" if it exists
    fn patch(&self) -> PathBuf;
}
impl<T: AsRef<Path>> Git2Patch for T {
    fn patch(&self) -> PathBuf {
        let path = self.as_ref().to_path_buf();

        #[cfg(target_family = "unix")]
        let mut prefix = "./".to_string();
        #[cfg(target_family = "windows")]
        let mut prefix = ".\\".to_string();

        let res = path.strip_prefix(&prefix);
        if let Ok(mut ok_stripped) = res {
            prefix.remove(0);
            while let Ok(stripped_again) = ok_stripped.strip_prefix(&prefix) {
                ok_stripped = stripped_again;
            }
            return ok_stripped.to_path_buf();
        }
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_family = "unix")]
    fn test_patch() {
        let patched = Path::new("src/utils/pathutils.rs");
        assert_eq!(patched.patch(), patched);
        let p = Path::new("./src/utils/pathutils.rs");
        assert_eq!(p.patch(), patched);
        let p = Path::new(".////src/utils/pathutils.rs");
        assert_eq!(p.patch(), patched);
    }

    #[test]
    #[cfg(target_family = "windows")]
    fn test_patch() {
        let patched = Path::new("src\\utils\\pathutils.rs");
        assert_eq!(patched.patch(), patched);
        let p = Path::new(".\\src\\utils\\pathutils.rs");
        assert_eq!(p.patch(), patched);
        let p = Path::new(".\\\\\\\\src\\utils\\pathutils.rs");
        assert_eq!(p.patch(), patched);
    }
}
