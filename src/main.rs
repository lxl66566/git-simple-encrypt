use clap::Parser;
use git_simple_encrypt::{Cli, run};
use log::LevelFilter;

fn main() -> anyhow::Result<()> {
    log_init();
    run(&Cli::parse())
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
