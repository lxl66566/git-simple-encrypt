use std::sync::{Arc, OnceLock};

use argon2::Argon2;
use dashmap::DashMap;
use zeroize::Zeroizing;

use crate::{
    crypt::header::{FILE_ID_LEN, NONCE_LEN, SALT_LEN},
    error::{Error, Result},
};

pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(password, salt, &mut *key)
        .map_err(|e| Error::Argon2(e.to_string()))?;
    Ok(key)
}

pub(super) fn split_keys(master_key: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let key_enc = blake3::derive_key("git-simple-encrypt-enc", master_key);
    let key_mac = blake3::derive_key("git-simple-encrypt-mac", master_key);
    (Zeroizing::new(key_enc), Zeroizing::new(key_mac))
}

pub(super) fn derive_nonce(
    key_mac: &[u8; 32],
    file_id: &[u8; FILE_ID_LEN],
    plaintext: &[u8],
    chunk_idx: u64,
) -> [u8; NONCE_LEN] {
    let mut hasher = blake3::Hasher::new_keyed(key_mac);
    hasher.update(file_id);
    hasher.update(plaintext);
    hasher.update(&chunk_idx.to_le_bytes());
    let hash = hasher.finalize();
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&hash.as_bytes()[..NONCE_LEN]);
    nonce
}

pub(super) type KeyCache =
    DashMap<[u8; SALT_LEN], Arc<OnceLock<Result<Zeroizing<[u8; 32]>, String>>>>;

pub(super) fn get_or_derive_key(
    key_cache: &KeyCache,
    master_key: &[u8],
    salt: &[u8; SALT_LEN],
) -> Result<Zeroizing<[u8; 32]>> {
    let lock = {
        let guard = key_cache
            .entry(*salt)
            .or_insert_with(|| Arc::new(OnceLock::new()));
        Arc::clone(&*guard)
    };

    match lock.get_or_init(|| derive_key(master_key, salt).map_err(|e| e.to_string())) {
        Ok(key) => Ok(key.clone()),
        Err(msg) => Err(Error::Argon2(msg.clone())),
    }
}
