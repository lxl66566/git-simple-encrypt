#![warn(clippy::nursery, clippy::cargo, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::multiple_crate_versions)]

mod cli;
mod config;
pub mod crypt;
mod repo;
mod salt_cache;
mod utils;

use anyhow::Result;
use assert2::assert;
use crypt::{decrypt_repo, encrypt_repo};
use repo::Repo;

pub use crate::{
    cli::{Cli, SetField, SubCommand},
    crypt::FileHeader,
};

#[allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]
pub fn run(cli: Cli) -> Result<()> {
    assert!(cli.repo.is_absolute(), "repo path must be absolute");
    let repo = Repo::open(&cli.repo)?;
    let repo = Box::leak(Box::new(repo));
    match cli.command {
        SubCommand::Encrypt { paths } => encrypt_repo(repo, paths)?,
        SubCommand::Decrypt { paths } => decrypt_repo(repo, paths)?,
        SubCommand::Add { paths } => repo.conf.add_paths_to_crypt_list(&paths)?,
        SubCommand::Set { field } => field.set(repo)?,
        SubCommand::Pwd => repo.set_key_interactive()?,
    }
    anyhow::Ok::<()>(())
}
