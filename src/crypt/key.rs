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

/// Derive only the AEAD key. Decrypt paths read per-chunk nonces from the
/// ciphertext and never need `key_mac`, so they skip one blake3 KDF by
/// calling this instead of [`split_keys`].
pub(super) fn split_key_enc(master_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key("git-simple-encrypt-enc", master_key))
}

fn split_key_mac(master_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key("git-simple-encrypt-mac", master_key))
}

pub(super) fn split_keys(master_key: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    (split_key_enc(master_key), split_key_mac(master_key))
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

/// How a decrypt call obtains the Argon2-derived key for a file's salt.
pub(super) enum KeyDerivation<'a> {
    /// Run Argon2 on every call (single-file public entry points).
    Direct,
    /// Deduplicate Argon2 across files that share a salt (batch/repo paths).
    Shared(&'a KeyCache),
}

impl KeyDerivation<'_> {
    pub(super) fn derive(
        self,
        master_key: &[u8],
        salt: &[u8; SALT_LEN],
    ) -> Result<Zeroizing<[u8; 32]>> {
        match self {
            Self::Direct => derive_key(master_key, salt),
            Self::Shared(cache) => get_or_derive_key(cache, master_key, salt),
        }
    }
}

pub(super) fn get_or_derive_key(
    key_cache: &KeyCache,
    master_key: &[u8],
    salt: &[u8; SALT_LEN],
) -> Result<Zeroizing<[u8; 32]>> {
    // Fast path: `get` takes only the shard read-lock (and drops the guard
    // before Argon2 runs). `entry()` always takes the exclusive lock, which
    // would serialize worker threads looking up an already-derived salt.
    let lock = key_cache.get(salt).map_or_else(
        || {
            Arc::clone(
                &*key_cache
                    .entry(*salt)
                    .or_insert_with(|| Arc::new(OnceLock::new())),
            )
        },
        |guard| Arc::clone(guard.value()),
    );

    match lock.get_or_init(|| derive_key(master_key, salt).map_err(|e| e.to_string())) {
        Ok(key) => Ok(key.clone()),
        Err(msg) => Err(Error::Argon2(msg.clone())),
    }
}
