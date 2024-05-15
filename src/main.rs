use clap::Parser;
use git_simple_encrypt::{run, Cli};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    run(&Cli::parse()).await
}
