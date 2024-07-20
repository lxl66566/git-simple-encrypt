use clap::Parser;
use git_simple_encrypt::{run, Cli};

fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .format_target(false)
        .format_timestamp(None)
        .init();
    run(&Cli::parse())
}
