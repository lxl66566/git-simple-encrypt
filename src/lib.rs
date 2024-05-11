#![feature(lazy_cell)]
#![feature(vec_pop_if)]
#![feature(let_chains)]
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
use utils::{Git2Patch, PathToUnixStyle};

pub use crate::cli::{Cli, SubCommand};

pub async fn run(cli: &Cli) -> Result<()> {
    let mut repo = Repo::open(&cli.repo)?;
    match &cli.command {
        SubCommand::Encrypt => encrypt_repo(&repo).await?,
        SubCommand::Decrypt => decrypt_repo(&repo).await?,
        SubCommand::Add { path } => {
            let paths_patch = &path
                .iter()
                .map(|p| p.to_unix_style().patch().to_string_lossy().to_string())
                .collect::<Vec<String>>();
            repo.conf
                .add_to_crypt_list(&paths_patch.iter().map(|s| s.as_ref()).collect::<Vec<_>>())
        }
        SubCommand::Set { field, value } => field.set(&mut repo, value)?,
    }
    Ok(())
}
