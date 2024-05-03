use crate::crypt::ENCRYPTED_EXTENSION;
use std::{
    fs::OpenOptions,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use tap::Tap;

#[cfg(unix)]
pub const END_OF_LINE: &str = "\n";
#[cfg(windows)]
pub const END_OF_LINE: &str = "\r\n";

#[cfg(unix)]
pub fn bytes2path(b: &[u8]) -> &Path {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
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

pub trait BetterStripPrefix {
    fn strip_prefix_better(&mut self, prefix: impl AsRef<Path>) -> &mut Self;
}
impl BetterStripPrefix for PathBuf {
    fn strip_prefix_better(&mut self, prefix: impl AsRef<Path>) -> &mut Self {
        if let Ok(res) = self.strip_prefix(prefix) {
            *self = res.to_path_buf();
        }
        self
    }
}

/// (written by GPT) append str to the end of file. If file is not ends with
/// '\n', just add it.
pub fn append_line_to_file(path: impl AsRef<Path>, line: &str) -> io::Result<()> {
    // 打开文件，如果文件不存在则创建它
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;

    // 将光标移动到文件的末尾
    let len = file.seek(SeekFrom::End(0))?;

    if len > 0 {
        // 移动光标到倒数第一个字符
        file.seek(SeekFrom::End(-1))?;
        let mut last_char = [0u8];
        // 读取最后一个字符
        file.read_exact(&mut last_char)?;

        // 如果最后一个字符不是换行符，则添加一个换行符
        if last_char[0] != b'\n' {
            file.write_all(b"\n")?;
        }
    }

    // 添加新的一行
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Ok;
    use std::fs;
    use temp_testdir::TempDir;

    #[test]
    fn test_append_line_to_file() -> anyhow::Result<()> {
        let temp_dir = TempDir::default();
        let file = temp_dir.join("test1");

        let line = "123";
        fs::write(&file, line)?;
        append_line_to_file(&file, line).unwrap();
        assert_eq!(fs::read_to_string(&file)?.trim(), "123\n123");
        let line = "123\n";
        fs::write(&file, line)?;
        append_line_to_file(&file, line).unwrap();
        assert_eq!(fs::read_to_string(&file)?.trim(), "123\n123");
        Ok(())
    }
}
