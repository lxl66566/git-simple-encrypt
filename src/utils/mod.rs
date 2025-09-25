pub mod pathutils;

use std::io::Write;

use anyhow::Result;
use assert2::assert;

/// Format a byte array into a hex string
#[cfg(any(test, debug_assertions))]
pub fn format_hex(value: &[u8]) -> String {
    use std::fmt::Write;
    value.iter().fold(String::new(), |mut output, b| {
        let _ = write!(output, "{b:02x}");
        output
    })
}

/// Prompt the user for a password
pub fn prompt_password(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut password = String::new();
    std::io::stdin().read_line(&mut password)?;
    assert!(!password.is_empty(), "Password must not be empty");
    Ok(password.trim().to_string())
}
