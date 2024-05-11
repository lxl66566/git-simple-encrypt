use clap::Parser;
use git_simple_encrypt::{run, Cli};

#[compio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    run(&Cli::parse()).await
}
