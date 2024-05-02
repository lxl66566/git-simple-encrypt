use crate::{git_command::KEY, utils::AppendExt};
use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes128GcmSiv, Nonce,
};
use anyhow::{anyhow, Context};
use log::{debug, info};
use sha3::{Digest, Sha3_224};
use std::{ops::Deref, path::Path, sync::LazyLock as Lazy};

type Result<T> = std::result::Result<T, aes_gcm_siv::Error>;

static NONCE: Lazy<&Nonce> = Lazy::new(|| Nonce::from_slice(b"samenonceplz"));
pub static ENCRYPTED_EXTENSION: &str = "enc";

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

/// encrypt file, and unlink it.
pub async fn encrypt_file(file: impl AsRef<Path>) -> anyhow::Result<()> {
    info!("Encrypting file: {:?}", file.as_ref());
    let bytes = compio::fs::read(file.as_ref())
        .await
        .with_context(|| format!("{:?}", file.as_ref()))?;
    let new_file = file.as_ref().to_owned().append_ext();
    debug!("Encrypted filename: {:?}", new_file);
    compio::fs::write(
        &new_file,
        encrypt(KEY.as_bytes(), &bytes).map_err(|e| anyhow!("`{:?}`: {e}", new_file))?,
    )
    .await
    .0?;
    compio::fs::remove_file(file.as_ref()).await?;
    Ok(())
}

/// decrypt file, and unlink it.
pub async fn decrypt_file(file: impl AsRef<Path>) -> anyhow::Result<()> {
    debug_assert!(file.as_ref().extension().unwrap() == ENCRYPTED_EXTENSION);
    info!("Decrypting file: {:?}", file.as_ref());
    let bytes = compio::fs::read(&file)
        .await
        .with_context(|| format!("{:?}", file.as_ref()))?;
    let mut new_file = file.as_ref().to_owned();
    new_file.set_extension("");
    debug!("Decrypted filename: {:?}", new_file);
    compio::fs::write(
        &new_file,
        decrypt(KEY.as_bytes(), &bytes).map_err(|e| anyhow!("`{:?}`: {e}", new_file))?,
    )
    .await
    .0?;
    compio::fs::remove_file(&file).await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use anyhow::Ok;

    use super::*;
    use std::env::temp_dir;

    #[compio::test]
    async fn test_encrypt_decrypt() -> anyhow::Result<()> {
        const CONTENT: &[u8; 6] = b"123456";
        let file = temp_dir().join("test_file.txt");
        std::fs::write(&file, CONTENT)?;
        encrypt_file(&file).await?;
        let encrypted_file = file.parent().unwrap().join("test_file.txt.enc");

        assert!(!file.exists());
        assert!(encrypted_file.exists());
        assert_ne!(CONTENT.to_vec(), std::fs::read(&encrypted_file)?);

        decrypt_file(&encrypted_file).await?;
        assert_eq!(std::fs::read_to_string(&file)?, "123456");

        std::fs::remove_file(&file)?;
        Ok(())
    }
}
