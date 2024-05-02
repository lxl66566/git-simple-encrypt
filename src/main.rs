#![feature(lazy_cell)]

mod cli;
mod crypt;
mod git_command;
mod utils;

use anyhow::{Ok, Result};
use cli::{SubCommand, CLI};
use git_command::{
    add_crypt_attributes, decrypt_repo, encrypt_repo, remove_crypt_attributes, set_key,
};

#[compio::main]
async fn main() -> Result<()> {
    env_logger::init();
    match &CLI.command {
        SubCommand::Encrypt => encrypt_repo().await?,
        SubCommand::Decrypt => decrypt_repo().await?,
        SubCommand::Set { key } => set_key(key)?,
        SubCommand::Add { path } => add_crypt_attributes(path)?,
        SubCommand::Remove { path } => remove_crypt_attributes(path)?,
    }
    Ok(())
}
