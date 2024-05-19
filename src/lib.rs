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

use anyhow::Result;
use crypt::{decrypt_repo, encrypt_repo};
use log::debug;
use repo::Repo;
use tokio::runtime::Builder;

pub use crate::cli::{Cli, SetField, SubCommand};

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
            SubCommand::Decrypt { path } => decrypt_repo(repo, path).await?,
            SubCommand::Add { paths } => repo
                .conf
                .add_to_crypt_list(&paths.iter().map(|s| s.as_ref()).collect::<Vec<_>>())?,
            SubCommand::Set { field, value } => field.set(repo, value)?,
        }
        anyhow::Ok::<()>(())
    })
}
