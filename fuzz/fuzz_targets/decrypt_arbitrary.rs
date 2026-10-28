#![no_main]

//! Arbitrary bytes as a GITSE ciphertext: decryption must return cleanly
//! (Ok or Err) — a panic, a hang or a memory error is a bug.

use std::io::Cursor;

use git_simple_encrypt::{
    crypt::{KeyDerivation, SALT_LEN, decrypt_into_with},
    fuzzing::{key_cache, normalize_header_salts},
};
use git_simple_encrypt_fuzz::{install_panic_hook, run};
use libfuzzer_sys::fuzz_target;

const MASTER_PASSWORD: &[u8] = b"git-se-fuzz-password";
const SALT: [u8; SALT_LEN] = *b"git-se-fuzz-salt";

fuzz_target!(init: install_panic_hook(), |data: &[u8]| {
    run(data, |data| {
        let mut bytes = data.to_vec();
        // A fixed salt keeps the Argon2 derivation cached for the whole run.
        normalize_header_salts(&mut bytes, SALT);
        let mut out = Vec::new();
        let _ = decrypt_into_with(
            &mut Cursor::new(&bytes),
            &mut out,
            MASTER_PASSWORD,
            KeyDerivation::Shared(key_cache()),
        );
    });
});
