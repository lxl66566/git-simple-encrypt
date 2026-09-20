use clap::Parser;
use git_simple_encrypt::{Cli, run};
use log::LevelFilter;

fn main() {
    log_init();
    // Report failures through Display (user-facing message) instead of the
    // derived Debug output std prints for an `Err` returned from main. The
    // exit code stays 1, matching the `Result`-returning form.
    if let Err(e) = run(Cli::parse()) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

#[inline]
pub fn log_init() {
    #[cfg(not(debug_assertions))]
    log_init_with_default_level(LevelFilter::Info);
    #[cfg(debug_assertions)]
    log_init_with_default_level(LevelFilter::Debug);
}

#[inline]
pub fn log_init_with_default_level(level: LevelFilter) {
    _ = pretty_env_logger::formatted_builder()
        .filter_level(level)
        .format_timestamp_millis()
        .parse_default_env()
        .try_init();
}
