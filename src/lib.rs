#![warn(clippy::nursery, clippy::cargo, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::multiple_crate_versions)]

#[cfg(feature = "bin")]
mod cli;
pub mod config;
pub mod crypt;
mod error;
pub mod filter;
pub mod gitattributes;
pub mod repo;
pub mod salt_cache;
pub mod utils;

#[cfg(feature = "bin")]
pub use crate::cli::{Cli, InstallMode, SetField, SubCommand};
#[cfg(feature = "bin")]
use crate::crypt::{decrypt_repo, encrypt_repo};
#[cfg(feature = "bin")]
use crate::repo::Repo;
pub use crate::{
    crypt::{BatchSummary, FileHeader},
    error::{Error, Result},
};

/// Dispatch a parsed CLI invocation.
///
/// Only available with the `bin` feature (default for the `git-se` binary).
#[cfg(feature = "bin")]
pub fn run(cli: Cli) -> Result<()> {
    if !cli.repo.is_absolute() {
        return Err(Error::RepoPathNotAbsolute(cli.repo.clone()));
    }
    // Every command resolves the repo the same way: `discover` walks up from
    // the given directory, so invocations from anywhere inside the worktree
    // (subdirectories included — what the discover docs promise) work for
    // filter drivers and manual commands alike; at the repo root it behaves
    // exactly like `Repo::open`.
    let mut repo = Repo::discover(&cli.repo)?;
    match cli.command {
        SubCommand::Encrypt { paths } => encrypt_repo(&repo, &paths)?,
        SubCommand::Decrypt { paths } => decrypt_repo(&repo, &paths)?,
        SubCommand::Add { paths } => {
            repo.conf.add_paths_to_crypt_list(&paths)?;
            // Keep the managed .gitattributes block in sync in filter mode.
            repo.refresh_gitattributes()?;
        },
        SubCommand::Set { field } => field.set(&mut repo)?,
        SubCommand::Pwd => repo.set_key_interactive()?,
        SubCommand::Check { paths, staged } => repo.check(&paths, staged)?,
        SubCommand::Install { mode } => match mode {
            InstallMode::Filter => repo.install_filter()?,
            InstallMode::Hook => repo.install_hook()?,
        },
        SubCommand::Clean { path } => filter::clean(&repo, &path)?,
        SubCommand::Smudge { path } => filter::smudge(&repo, &path)?,
        SubCommand::Diff { file } => filter::diff(&repo, file.as_deref())?,
        SubCommand::FilterProcess => filter::process::serve(&repo)?,
    }
    Ok(())
}
