#![feature(lazy_cell)]

mod cli;
mod crypt;
mod git_command;
mod utils;

use anyhow::{Ok, Result};
use cli::{SubCommand, CLI};
use git_command::{decrypt_repo, encrypt_repo, set_key};

#[compio::main]
async fn main() -> Result<()> {
    env_logger::init();
    match &CLI.command {
        SubCommand::Encrypt => encrypt_repo().await?,
        SubCommand::Decrypt => decrypt_repo().await?,
        SubCommand::Set { key } => set_key(key)?,
        _ => unimplemented!(),
    }
    Ok(())
}
