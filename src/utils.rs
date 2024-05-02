use crate::crypt::ENCRYPTED_EXTENSION;
use std::path::{Path, PathBuf};
use tap::Tap;

#[cfg(unix)]
pub fn bytes2path(b: &[u8]) -> &Path {
    use std::os::unix::prelude::*;
    Path::new(OsStr::from_bytes(b))
}
#[cfg(windows)]
pub fn bytes2path(b: &[u8]) -> &Path {
    use std::str;
    Path::new(str::from_utf8(b).unwrap())
}

pub trait AppendExt {
    fn append_ext(self) -> PathBuf;
}
impl AppendExt for PathBuf {
    fn append_ext(self) -> PathBuf {
        self.tap_mut(|p| p.as_mut_os_string().push(format!(".{ENCRYPTED_EXTENSION}")))
    }
}
