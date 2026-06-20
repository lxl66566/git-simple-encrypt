//! Colored terminal output helpers.
//!
//! When the `colored` feature is enabled, this module re-exports the
//! `colored::Colorize` trait so you can write `"text".bold()` etc.
//! When disabled, a minimal no-op `Colorize` trait provides the same
//! method signatures, returning the input string unchanged. Callers
//! always `use crate::utils::style::Colorize` and never need `#[cfg]`.

/// Colorize strings for terminal display.
///
/// When `feature = "colored"`, this is an alias for [`colored::Colorize`];
/// the underlying `colored` crate adds ANSI escape codes. When the feature
/// is off, every method is a no-op that returns the string as-is.
#[cfg(feature = "colored")]
pub use colored::Colorize;

/// Colorize strings for terminal display (no-op fallback).
#[cfg(not(feature = "colored"))]
pub trait Colorize {
    /// Bold style.
    fn bold(self) -> String;
    /// Green foreground.
    fn green(self) -> String;
    /// Red foreground.
    fn red(self) -> String;
    /// Yellow foreground.
    fn yellow(self) -> String;
    /// Cyan foreground.
    fn cyan(self) -> String;
    /// Dimmed style.
    fn dimmed(self) -> String;
}

#[cfg(not(feature = "colored"))]
impl<'a> Colorize for &'a str {
    fn bold(self) -> String {
        self.to_string()
    }
    fn green(self) -> String {
        self.to_string()
    }
    fn red(self) -> String {
        self.to_string()
    }
    fn yellow(self) -> String {
        self.to_string()
    }
    fn cyan(self) -> String {
        self.to_string()
    }
    fn dimmed(self) -> String {
        self.to_string()
    }
}

#[cfg(not(feature = "colored"))]
impl Colorize for String {
    fn bold(self) -> String {
        self
    }
    fn green(self) -> String {
        self
    }
    fn red(self) -> String {
        self
    }
    fn yellow(self) -> String {
        self
    }
    fn cyan(self) -> String {
        self
    }
    fn dimmed(self) -> String {
        self
    }
}
