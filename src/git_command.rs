use std::process::Command;
use std::sync::LazyLock as Lazy;

const KEY_NAME: &str = "simple-git-encrypt.key";

pub static KEY: Lazy<String> = Lazy::new(|| {
    let output = Command::new("git")
        .arg("config")
        .arg("get")
        .arg(KEY_NAME)
        .output()
        .expect("failed to execute process to get KEY.");

    String::from_utf8_lossy(&output.stdout).trim().to_string()
});
