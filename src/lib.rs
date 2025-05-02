#![feature(let_chains)]
#![feature(test)]
#![warn(clippy::nursery, clippy::cargo, clippy::pedantic)]
#![allow(clippy::multiple_crate_versions)]

mod cli;
mod config;
mod crypt;
mod repo;
mod utils;

use anyhow::Result;
use crypt::{decrypt_repo, encrypt_repo};
use repo::Repo;

pub use crate::cli::{Cli, SetField, SubCommand};

#[allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]
pub fn run(cli: Cli) -> Result<()> {
    let repo = Repo::open(&cli.repo)?;
    let repo = Box::leak(Box::new(repo));
    match cli.command {
        SubCommand::Encrypt => encrypt_repo(repo)?,
        SubCommand::Decrypt { path } => decrypt_repo(repo, path)?,
        SubCommand::Add { paths } => repo.conf.add_to_crypt_list(&paths)?,
        SubCommand::Set { field } => field.set(repo)?,
        SubCommand::Pwd => repo.set_key_interactive()?,
    }
    anyhow::Ok::<()>(())
}
