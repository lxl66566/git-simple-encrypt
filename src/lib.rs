#![warn(clippy::nursery, clippy::cargo, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::multiple_crate_versions)]

pub mod config;
pub mod crypt;
mod error;
pub mod repo;
pub mod salt_cache;
pub mod utils;

#[cfg(feature = "bin")]
mod cli;

#[cfg(feature = "bin")]
use crate::crypt::{decrypt_repo, encrypt_repo};
#[cfg(feature = "bin")]
use crate::repo::Repo;

pub use crate::error::{Error, Result};

pub use crate::crypt::FileHeader;

#[cfg(feature = "bin")]
pub use crate::cli::{Cli, SetField, SubCommand};

/// Dispatch a parsed CLI invocation.
///
/// Only available with the `bin` feature (default for the `git-se` binary).
#[cfg(feature = "bin")]
pub fn run(cli: Cli) -> Result<()> {
    if !cli.repo.is_absolute() {
        return Err(Error::RepoPathNotAbsolute(cli.repo.clone()));
    }
    let mut repo = Repo::open(&cli.repo)?;
    match cli.command {
        SubCommand::Encrypt { paths } => encrypt_repo(&repo, &paths)?,
        SubCommand::Decrypt { paths } => decrypt_repo(&repo, &paths)?,
        SubCommand::Add { paths } => repo.conf.add_paths_to_crypt_list(&paths)?,
        SubCommand::Set { field } => field.set(&mut repo)?,
        SubCommand::Pwd => repo.set_key_interactive()?,
        SubCommand::Check { paths, staged } => repo.check(&paths, staged)?,
        SubCommand::Install => repo.install_hook()?,
    }
    Ok(())
}
