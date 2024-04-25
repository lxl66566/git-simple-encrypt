#![feature(lazy_cell)]

mod cli;
mod crypt;
mod git_command;

use crate::crypt::{decrypt, encrypt};
use clap::Parser;
use cli::Cli;

type Result<T> = std::result::Result<T, aes_gcm_siv::Error>;

fn main() -> Result<()> {
    let cli = Cli::parse();
    println!("{:?}", cli);
    let plaintext = b"Hello, world!";
    let key = b"l".iter().cycle().take(128).copied().collect::<Vec<u8>>();
    let ciphertext = encrypt(&key, plaintext)?;
    println!("Ciphertext: {:?}", ciphertext);
    let plaintext = decrypt(&key, &ciphertext)?;
    println!("Decrypted: {:?}", plaintext);
    Ok(())
}
