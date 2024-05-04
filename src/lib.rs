#![feature(lazy_cell)]
#![feature(vec_pop_if)]
#![feature(let_chains)]
#![warn(clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

mod cli;
mod crypt;
mod git_command;
mod utils;

use anyhow::{Ok, Result};
use git_command::{
    add_crypt_attributes, config, decrypt_repo, encrypt_repo, remove_crypt_attributes,
};

pub use crate::cli::{SubCommand, CLI};

pub async fn run(command: &SubCommand) -> Result<()> {
    match command {
        SubCommand::Encrypt => encrypt_repo().await?,
        SubCommand::Decrypt => decrypt_repo().await?,
        SubCommand::SetKey { key } => config::set_key(key)?,
        SubCommand::Add { path } => add_crypt_attributes(path)?,
        SubCommand::Remove { path } => remove_crypt_attributes(path)?,
        SubCommand::Set { field, value } => config::set(field.name(), value)?,
    }
    Ok(())
}
