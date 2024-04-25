use crate::git_command::KEY;
use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes128GcmSiv, Nonce,
};
use anyhow::anyhow;
use sha3::{Digest, Sha3_224};
use std::{ops::Deref, path::PathBuf, sync::LazyLock as Lazy};

type Result<T> = std::result::Result<T, aes_gcm_siv::Error>;

static NONCE: Lazy<&Nonce> = Lazy::new(|| Nonce::from_slice(b"samenonceplz"));
static ENCRYPTED_EXTENSION: &str = ".enc";

pub fn encrypt(key: &[u8], text: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = Sha3_224::default();
    hasher.update(key);
    let cipher = Aes128GcmSiv::new_from_slice(&hasher.finalize().as_slice()[..16])
        .expect("cipher key length error.");
    let ciphertext = cipher.encrypt(NONCE.deref(), text)?;
    Ok(ciphertext)
}

pub fn decrypt(key: &[u8], text: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = Sha3_224::default();
    hasher.update(key);
    let cipher = Aes128GcmSiv::new_from_slice(&hasher.finalize().as_slice()[..16])
        .expect("cipher key length error.");
    let plaintext = cipher.decrypt(NONCE.deref(), text)?;
    Ok(plaintext)
}

pub async fn encrypt_file(file: PathBuf) -> anyhow::Result<()> {
    let bytes = tokio::fs::read(&file).await?;
    let mut new_file_name = file
        .file_name()
        .ok_or(anyhow!("cannot get file name"))?
        .to_owned();
    new_file_name.push(ENCRYPTED_EXTENSION);
    let mut new_file = file.clone();
    new_file.set_file_name(new_file_name);
    tokio::fs::write(
        new_file,
        encrypt(KEY.as_bytes(), &bytes)
            .map_err(|e| anyhow!("error occurs in encrypting bytes: {e}"))?,
    )
    .await?;
    Ok(())
}
