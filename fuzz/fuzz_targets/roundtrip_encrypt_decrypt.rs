#![no_main]

//! Encrypt → decrypt roundtrip over structured inputs.
//!
//! Input layout: `[flags (1) | tail (1) | len_lo (1) | len_hi (1) | pattern..]`.
//! `flags` bit 0 enables Zstd compression (level from `tail`), bits 1-2 add
//! full 64 KiB chunks so single- and multi-chunk paths and their exact
//! boundaries all run. The payload is the pattern bytes repeated cyclically
//! to the target length.

use std::io::Cursor;

use git_simple_encrypt::{
    crypt::{
        CHUNK_SIZE, FILE_ID_LEN, KeyDerivation, SALT_LEN, decrypt_into_with, encrypt_into,
        get_or_derive_key,
    },
    fuzzing::key_cache,
};
use git_simple_encrypt_fuzz::{install_panic_hook, run};
use libfuzzer_sys::fuzz_target;

const MASTER_PASSWORD: &[u8] = b"git-se-fuzz-password";
const SALT: [u8; SALT_LEN] = *b"git-se-fuzz-salt";
const FILE_ID: [u8; FILE_ID_LEN] = *b"git-se-fuzz-file";

fuzz_target!(init: install_panic_hook(), |data: &[u8]| {
    run(data, |data| {
        if data.len() < 4 {
            return;
        }
        let flags = data[0];
        let use_zstd = flags & 1 != 0;
        let chunk_extra = usize::from((flags >> 1) & 0b11) * CHUNK_SIZE;
        let base_len = usize::from(u16::from_le_bytes([data[2], data[3]]));
        let zstd_level = data[1] % 22 + 1;
        // `data[1]`/`data[0]` double as the pattern head when the body is empty.
        let pattern: Vec<u8> = if data.len() > 4 {
            data[4..].to_vec()
        } else {
            vec![data[1], data[0], 0x00, 0xFF]
        };

        let payload: Vec<u8> =
            pattern.iter().copied().cycle().take(base_len + chunk_extra).collect();

        let derived_key = get_or_derive_key(key_cache(), MASTER_PASSWORD, &SALT)
            .expect("Argon2 derivation of a fixed (password, salt) cannot fail");
        let mut ciphertext = Vec::new();
        let header = encrypt_into(
            &mut Cursor::new(&payload),
            &mut ciphertext,
            &derived_key,
            SALT,
            Some(FILE_ID),
            use_zstd.then_some(zstd_level),
        )
        .expect("encrypting any payload must succeed");

        let mut recovered = Vec::new();
        let header2 = decrypt_into_with(
            &mut Cursor::new(&ciphertext),
            &mut recovered,
            MASTER_PASSWORD,
            KeyDerivation::Shared(key_cache()),
        )
        .expect("our own ciphertext must decrypt");

        assert_eq!(recovered, payload, "roundtrip mismatch");
        assert_eq!(header2, header, "header must survive the roundtrip");
        assert_eq!(header2.is_compressed(), use_zstd);
    });
});
