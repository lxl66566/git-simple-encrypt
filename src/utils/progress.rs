//! Progress reporting abstraction.
//!
//! When the `progress` feature is enabled, [`Progress`] wraps an
//! `indicatif::ProgressBar`. When disabled, it is a zero-sized type and
//! progress is reported only via `log::info!` at start/finish. Either way
//! the call-site API is identical, so `crypt::encrypt_repo` and friends do
//! not need any feature gates.

#[cfg(feature = "progress")]
use indicatif::{ProgressBar, ProgressStyle};

/// Monomorphic progress handle used by repo-wide operations.
///
/// `Send + Sync` so it can be shared (by reference) across rayon workers.
pub struct Progress {
    #[cfg(feature = "progress")]
    inner: ProgressBar,
}

impl Progress {
    /// Create a new progress handle for `len` items with a short label.
    #[must_use]
    pub fn new(len: usize, prefix: &'static str) -> Self {
        // Always log the start line so non-progress lib users still see output.
        log::info!("{prefix}: {len} files");
        Self {
            #[cfg(feature = "progress")]
            inner: make_indicatif(len, prefix),
        }
    }

    /// Advance the progress by `n` finished items.
    #[inline]
    pub fn inc(&self, n: u64) {
        #[cfg(feature = "progress")]
        self.inner.inc(n);
        // No-op without the feature; per-item logging would be too noisy.
        #[cfg(not(feature = "progress"))]
        let _ = n;
    }

    /// Finalize and clear the progress bar (if any).
    #[inline]
    pub fn finish_and_clear(&self) {
        #[cfg(feature = "progress")]
        self.inner.finish_and_clear();
    }
}

#[cfg(feature = "progress")]
fn make_indicatif(len: usize, prefix: &'static str) -> ProgressBar {
    let pb = ProgressBar::new(len as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{prefix:.bold} {bar:40.cyan/blue} {pos}/{len} {spinner} [{elapsed_precise}]",
        )
        .expect("valid indicatif template")
        .progress_chars("#>-"),
    );
    pb.set_prefix(prefix);
    pb.enable_steady_tick(std::time::Duration::from_millis(200));
    pb
}
