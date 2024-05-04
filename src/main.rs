use git_simple_encrypt::{run, CLI};

#[compio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    run(&CLI.command).await
}
