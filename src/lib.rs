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
use log::debug;
use repo::Repo;
use tokio::runtime::Builder;

pub use crate::cli::{Cli, SetField, SubCommand};

#[allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]
pub fn run(cli: &Cli) -> Result<()> {
    let repo = Repo::open(&cli.repo)?;
    let repo = Box::leak(Box::new(repo));
    let num_cpus = num_cpus::get();
    debug!("using blocking thread size: {}", num_cpus * 2);
    let rt = Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(num_cpus * 2)
        .build()
        .unwrap();
    rt.block_on(async {
        match &cli.command {
            SubCommand::Encrypt => encrypt_repo(repo).await?,
            SubCommand::Decrypt { path } => decrypt_repo(repo, path.as_ref()).await?,
            SubCommand::Add { paths } => repo.conf.add_to_crypt_list(
                &paths
                    .iter()
                    .map(std::convert::AsRef::as_ref)
                    .collect::<Vec<_>>(),
            )?,
            SubCommand::Set { field } => field.set(repo)?,
            SubCommand::Pwd => repo.set_key_interactive()?,
        }
        anyhow::Ok::<()>(())
    })
}
