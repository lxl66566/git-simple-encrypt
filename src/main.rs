#![feature(lazy_cell)]
#![feature(vec_pop_if)]
#![feature(let_chains)]
#![warn(clippy::nursery, clippy::cargo)]

mod cli;
mod crypt;
mod git_command;
mod utils;

use anyhow::{Ok, Result};
use cli::{SubCommand, CLI};
use git_command::{
    add_crypt_attributes, config, decrypt_repo, encrypt_repo, remove_crypt_attributes,
};

#[compio::main]
async fn main() -> Result<()> {
    env_logger::init();
    match &CLI.command {
        SubCommand::Encrypt => encrypt_repo().await?,
        SubCommand::Decrypt => decrypt_repo().await?,
        SubCommand::Set { field, value } => config::set(field, value)?,
        SubCommand::Add { path } => add_crypt_attributes(path)?,
        SubCommand::Remove { path } => remove_crypt_attributes(path)?,
    }
    Ok(())
}
