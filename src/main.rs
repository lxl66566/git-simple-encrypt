use clap::Parser;
use git_simple_encrypt::{run, Cli};

fn main() -> anyhow::Result<()> {
    env_logger::init();
    run(&Cli::parse())
}
