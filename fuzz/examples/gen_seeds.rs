//! Generate the initial corpus seeds into `fuzz/seeds/<target>/`.
//!
//! Run from the fuzz crate: `cargo run --example gen_seeds`.

use std::{collections::HashMap, fs, io::Cursor, path::Path};

use git_simple_encrypt::{
    crypt::{FILE_ID_LEN, SALT_LEN, encrypt_into, get_or_derive_key},
    fuzzing::key_cache,
    salt_cache::CachedEntry,
};

const MASTER_PASSWORD: &[u8] = b"git-se-fuzz-password";
const SALT: [u8; SALT_LEN] = *b"git-se-fuzz-salt";
const FILE_ID: [u8; FILE_ID_LEN] = *b"git-se-fuzz-file";

fn main() {
    let seeds = Path::new(env!("CARGO_MANIFEST_DIR")).join("seeds");
    fs::create_dir_all(&seeds).unwrap();

    let derived = get_or_derive_key(key_cache(), MASTER_PASSWORD, &SALT).unwrap();

    // ---- decrypt_arbitrary: valid ciphertexts to mutate from ----
    let dir = seeds.join("decrypt_arbitrary");
    fs::create_dir_all(&dir).unwrap();
    write(
        &dir,
        "plain_small.gitse",
        &encrypt(&derived, b"hello git-se", None),
    );
    let body: Vec<u8> = (0..=u8::MAX).cycle().take(70_000).collect();
    write(
        &dir,
        "plain_multichunk.gitse",
        &encrypt(&derived, &body, None),
    );
    let compressible = "compress me please ".repeat(4000).into_bytes();
    write(
        &dir,
        "compressed.gitse",
        &encrypt(&derived, &compressible, Some(3)),
    );
    let header_only = encrypt(&derived, b"body", None);
    write(&dir, "header_only.gitse", &header_only[..64]);
    // A structurally interesting header no current build decrypts.
    let mut future = vec![0u8; 64 + 4];
    future[..5].copy_from_slice(b"GITSE");
    future[5] = 4;
    future[7] = 1;
    future[64..].copy_from_slice(b"tail");
    write(&dir, "future_version.gitse", &future);

    // ---- process_filter_session: handshake + command scripts ----
    let dir = seeds.join("process_filter_session");
    fs::create_dir_all(&dir).unwrap();
    let ciphertext = encrypt(&derived, b"seed plaintext", None);
    let mut script = handshake_request();
    script.extend(command("clean", "seed.txt", b"seed plaintext"));
    script.extend(command("smudge", "seed.txt", &ciphertext));
    script.extend(command("clean", "seed.txt", b"seed plaintext"));
    write(&dir, "clean_smudge_session.bin", &script);
    let mut garbage = handshake_request();
    garbage.extend([0x00, 0x01, 0xff, 0xee]);
    write(&dir, "trailing_garbage.bin", &garbage);

    // ---- roundtrip: structured [flags | tail | len_lo | len_hi | pattern] ----
    let dir = seeds.join("roundtrip_encrypt_decrypt");
    fs::create_dir_all(&dir).unwrap();
    write(&dir, "small_plain.bin", &[
        0, 5, 16, 0, b'h', b'e', b'l', b'l', b'o',
    ]);
    write(&dir, "compressed.bin", &[1, 9, 200, 0, 0xaa, 0x55, 0x11]);
    // 65533 + 65536 bytes: crosses into the second chunk
    write(&dir, "two_chunks.bin", &[2, 3, 0xfd, 0xff, 0x42]);
    // exactly two full 64 KiB chunks, neither short
    write(&dir, "exact_two_chunks.bin", &[4, 3, 0x00, 0x00, 0x77]);
    write(&dir, "four_chunks.bin", &[6, 3, 0x01, 0x00, 0x99]);

    // ---- salt_cache_parse: a valid rkyv cache to mutate from ----
    let dir = seeds.join("salt_cache_parse");
    fs::create_dir_all(&dir).unwrap();
    let mut map = HashMap::new();
    map.insert(b"a.txt".to_vec(), CachedEntry {
        salt: [0x11; SALT_LEN],
        file_id: [0x22; FILE_ID_LEN],
    });
    map.insert(b"sub/b.txt".to_vec(), CachedEntry {
        salt: [0x33; SALT_LEN],
        file_id: [0x44; FILE_ID_LEN],
    });
    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&map).unwrap();
    write(&dir, "valid.cache", bytes.as_slice());

    println!("seeds written to {}", seeds.display());
}

fn encrypt(derived_key: &[u8; 32], plain: &[u8], zstd: Option<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    encrypt_into(
        &mut Cursor::new(plain),
        &mut out,
        derived_key,
        SALT,
        Some(FILE_ID),
        zstd,
    )
    .unwrap();
    out
}

fn write(dir: &Path, name: &str, bytes: &[u8]) {
    fs::write(dir.join(name), bytes).unwrap();
}

/// One LF-terminated text packet.
fn line(payload: &str) -> Vec<u8> {
    let payload = format!("{payload}\n");
    let mut v = format!("{:04x}", payload.len() + 4).into_bytes();
    v.extend_from_slice(payload.as_bytes());
    v
}

/// One binary data packet.
fn data(bytes: &[u8]) -> Vec<u8> {
    let mut v = format!("{:04x}", bytes.len() + 4).into_bytes();
    v.extend_from_slice(bytes);
    v
}

fn handshake_request() -> Vec<u8> {
    let mut v = line("git-filter-client");
    v.extend(line("version=2"));
    v.extend_from_slice(b"0000");
    v.extend(line("capability=clean"));
    v.extend(line("capability=smudge"));
    v.extend_from_slice(b"0000");
    v
}

fn command(command: &str, pathname: &str, content: &[u8]) -> Vec<u8> {
    let mut v = line(&format!("command={command}"));
    v.extend(line(&format!("pathname={pathname}")));
    v.extend(line("ref=refs/heads/main"));
    v.extend_from_slice(b"0000");
    for chunk in content.chunks(65516) {
        v.extend(data(chunk));
    }
    v.extend_from_slice(b"0000");
    v
}
