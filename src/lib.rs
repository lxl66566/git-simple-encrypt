#![feature(lazy_cell)]
#![feature(vec_pop_if)]
#![feature(let_chains)]
#![feature(absolute_path)]
#![warn(clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

mod cli;
mod config;
mod crypt;
mod repo;
mod utils;

use anyhow::{Ok, Result};
use crypt::{decrypt_repo, encrypt_repo};
use repo::Repo;

pub use crate::cli::{Cli, SetField, SubCommand};

pub async fn run(cli: &Cli) -> Result<()> {
    let mut repo = Repo::open(&cli.repo)?;
    match &cli.command {
        SubCommand::Encrypt => encrypt_repo(&repo).await?,
        SubCommand::Decrypt => decrypt_repo(&repo).await?,
        SubCommand::Add { path } => repo
            .conf
            .add_to_crypt_list(&path.iter().map(|s| s.as_ref()).collect::<Vec<_>>())?,
        SubCommand::Set { field, value } => field.set(&mut repo, value)?,
    }
    Ok(())
}
