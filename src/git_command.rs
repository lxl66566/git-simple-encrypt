use anyhow::anyhow;
use assert2::assert;
use die_exit::{Die, DieWith};
use std::process::Command;
use std::sync::LazyLock as Lazy;

const KEY_NAME: &str = "simple-git-encrypt.key";
const ATTR_NAME: &str = "crypt";

pub static KEY: Lazy<String> = Lazy::new(|| {
    let output = Command::new("git")
        .arg("config")
        .arg("get")
        .arg(KEY_NAME)
        .output()
        .die("Failed to get KEY. Please run `sge `");
    let temp = String::from_utf8(output.stdout)
        .die_with(|e| format!("Invalid char in KEY: {e}"))
        .trim()
        .to_string();
    assert!(!temp.is_empty(), "KEY is empty");
    temp
});

pub fn ls_files(pattern: &str) -> anyhow::Result<Vec<String>> {
    let output = Command::new("git")
        .arg("ls-files")
        .arg(format!("'{pattern}'"))
        .output()?
        .stdout;
    let files = String::from_utf8(output)
        .map_err(|e| anyhow!("Invalid char in filename: {e}"))?
        .trim()
        .to_string();
    let files = files.split('\n');
    let files = files.map(|s| s.to_string()).collect();
    Ok(files)
}

pub fn need_to_be_encrypted(path: &str) -> anyhow::Result<bool> {
    let output = Command::new("git")
        .args(["check-attr", ATTR_NAME, "--", path])
        .output()?
        .stdout;
    Ok(output.ends_with(b"set"))
}
