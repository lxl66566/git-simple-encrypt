use clap::Parser;
use git_simple_encrypt::{Cli, run};
use log::LevelFilter;

fn main() {
    let cli = Cli::parse();
    // Filter/textconv callbacks (per file, or one long-lived process filter
    // per git operation) have stdout carrying protocol/data streams; default
    // to error-only logging so they stay quiet. RUST_LOG still overrides
    // (see parse_default_env).
    let level = if cli.command.is_filter_driver() {
        LevelFilter::Error
    } else if cfg!(debug_assertions) {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    log_init_with_default_level(level);
    // Report failures through Display (user-facing message) instead of the
    // derived Debug output std prints for an `Err` returned from main. The
    // exit code stays 1, matching the `Result`-returning form.
    if let Err(e) = run(cli) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

#[inline]
pub fn log_init_with_default_level(level: LevelFilter) {
    _ = pretty_env_logger::formatted_builder()
        .filter_level(level)
        .format_timestamp_millis()
        .parse_default_env()
        .try_init();
}
