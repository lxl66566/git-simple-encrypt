use std::{
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
};

use dashmap::DashMap;
use rand::Rng;
use tempfile::{NamedTempFile, TempPath};

use super::{
    batch::*,
    file::*,
    header::*,
    key::*,
    stream::{decrypt_into, encrypt_into},
};

// --- Helper Functions ---

fn get_test_key_and_salt() -> ([u8; 32], [u8; SALT_LEN]) {
    let password = b"super_secret_password";
    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    let derived = derive_key(password, &salt).unwrap();
    let mut key = [0u8; 32];
    key.copy_from_slice(&*derived);
    (key, salt)
}

fn create_temp_file(content: &[u8]) -> TempPath {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(content).unwrap();
    file.flush().unwrap();
    file.into_temp_path()
}

// --- Tests ---

#[test]
fn test_header_serialization() {
    let salt = [0xAB; SALT_LEN];
    let file_id = FileHeader::generate_file_id();
    let header = FileHeader::new(true, salt, file_id);

    let mut buf = Vec::new();
    header.write_to(&mut buf).unwrap();
    assert_eq!(buf.len(), HEADER_LEN);

    let raw: &[u8; HEADER_LEN] = buf.as_slice().try_into().unwrap();
    let decoded = FileHeader::from_bytes(raw).unwrap();

    assert_eq!(decoded.magic, *MAGIC);
    assert_eq!(decoded.version, VERSION);
    assert_eq!(decoded.flags, FLAG_COMPRESSED);
    assert_eq!(decoded.enc_algo, ENC_ALGO);
    assert_eq!(decoded.salt, salt);
    assert_eq!(decoded.file_id, header.file_id);
    assert_eq!(decoded.reserved, [0u8; RESERVED_LEN]);
    assert!(decoded.is_compressed());
}

#[test]
fn test_nonce_derivation_deterministic() {
    let key_mac = [0x42u8; 32];
    let file_id = [0x99u8; FILE_ID_LEN];
    let plaintext = b"hello world";

    let nonce0_a = derive_nonce(&key_mac, &file_id, plaintext, 0);
    let nonce0_b = derive_nonce(&key_mac, &file_id, plaintext, 0);
    assert_eq!(nonce0_a, nonce0_b);

    let nonce1 = derive_nonce(&key_mac, &file_id, plaintext, 1);
    assert_ne!(nonce0_a, nonce1);

    let other_plaintext = b"hello world!";
    let nonce_other = derive_nonce(&key_mac, &file_id, other_plaintext, 0);
    assert_ne!(nonce0_a, nonce_other);

    let key_mac2 = [0x43u8; 32];
    let nonce_key2 = derive_nonce(&key_mac2, &file_id, plaintext, 0);
    assert_ne!(nonce0_a, nonce_key2);

    let file_id2 = [0xAAu8; FILE_ID_LEN];
    let nonce_file2 = derive_nonce(&key_mac, &file_id2, plaintext, 0);
    assert_ne!(nonce0_a, nonce_file2);

    let nonce_empty = derive_nonce(&key_mac, &file_id, b"", 0);
    assert_ne!(nonce_empty, [0u8; NONCE_LEN]);
}

#[test]
fn test_encrypt_decrypt_basic_no_compression() {
    let plaintext = b"Hello, World! This is a test without compression.";
    let path = create_temp_file(plaintext);

    let (key, salt) = get_test_key_and_salt();
    let master_key = b"super_secret_password";

    encrypt_file(&path, &key, &salt, None, None).unwrap();

    let mut encrypted_content = Vec::new();
    std::fs::File::open(&path)
        .unwrap()
        .read_to_end(&mut encrypted_content)
        .unwrap();
    assert_ne!(encrypted_content, plaintext);
    assert_eq!(&encrypted_content[0..5], MAGIC);
    assert_eq!(encrypted_content[5], VERSION);

    decrypt_file(&path, master_key).unwrap();

    let mut decrypted_content = Vec::new();
    std::fs::File::open(path)
        .unwrap()
        .read_to_end(&mut decrypted_content)
        .unwrap();
    assert_eq!(decrypted_content, plaintext);
}

#[test]
fn test_encrypt_decrypt_with_compression() {
    let plaintext = b"A".repeat(10000);
    let path = create_temp_file(&plaintext);

    let (key, salt) = get_test_key_and_salt();
    let master_key = b"super_secret_password";

    encrypt_file(&path, &key, &salt, None, Some(3)).unwrap();

    let encrypted_meta = std::fs::metadata(&path).unwrap();
    assert!(encrypted_meta.len() < 5000);

    decrypt_file(&path, master_key).unwrap();

    let mut decrypted_content = Vec::new();
    std::fs::File::open(path)
        .unwrap()
        .read_to_end(&mut decrypted_content)
        .unwrap();
    assert_eq!(decrypted_content, plaintext);
}

#[test]
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_sign_loss)]
fn test_chunked_encryption_large_file() {
    let plaintext = {
        let mut data = Vec::with_capacity(100_000);
        for i in 0..100_000 {
            data.push((i % 256) as u8);
        }
        data
    };

    let path = create_temp_file(&plaintext);

    let (key, salt) = get_test_key_and_salt();
    let master_key = b"super_secret_password";

    encrypt_file(&path, &key, &salt, None, None).unwrap();
    decrypt_file(&path, master_key).unwrap();

    let mut decrypted_content = Vec::new();
    std::fs::File::open(path)
        .unwrap()
        .read_to_end(&mut decrypted_content)
        .unwrap();
    assert_eq!(decrypted_content, plaintext);
}

#[test]
fn test_tamper_resistance() {
    let plaintext = b"Sensitive data that should not be tampered with.";
    let path = create_temp_file(plaintext);

    let (key, salt) = get_test_key_and_salt();
    let master_key = b"super_secret_password";

    encrypt_file(&path, &key, &salt, None, None).unwrap();

    let mut encrypted_content = Vec::new();
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    f.read_to_end(&mut encrypted_content).unwrap();

    encrypted_content[HEADER_LEN + 5] ^= 0xFF;

    f.seek(std::io::SeekFrom::Start(0)).unwrap();
    f.write_all(&encrypted_content).unwrap();
    drop(f);

    let result = decrypt_file(&path, master_key);

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .to_lowercase()
            .contains("decryption failed")
    );
}

#[test]
fn test_header_tamper_detected() {
    let plaintext = b"Test data with header integrity check.";
    let path = create_temp_file(plaintext);

    let (key, salt) = get_test_key_and_salt();
    let master_key = b"super_secret_password";

    encrypt_file(&path, &key, &salt, None, None).unwrap();

    let mut encrypted_content = Vec::new();
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    f.read_to_end(&mut encrypted_content).unwrap();

    encrypted_content[6] ^= FLAG_COMPRESSED;

    f.seek(std::io::SeekFrom::Start(0)).unwrap();
    f.write_all(&encrypted_content).unwrap();
    drop(f);

    let result = decrypt_file(&path, master_key);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .to_lowercase()
            .contains("decryption failed")
    );
}

#[test]
fn test_deterministic_encrypt_with_fixed_salt_file_id() {
    let plaintext = b"Deterministic encryption test data.";

    let password = b"test_password";
    let salt = [0x42; SALT_LEN];
    let file_id = [0x13; FILE_ID_LEN];
    let derived = derive_key(password, &salt).unwrap();
    let mut key = [0u8; 32];
    key.copy_from_slice(&*derived);

    let path1 = create_temp_file(plaintext);
    let path2 = create_temp_file(plaintext);

    encrypt_file(&path1, &key, &salt, Some(file_id), None).unwrap();
    encrypt_file(&path2, &key, &salt, Some(file_id), None).unwrap();

    let ct1 = std::fs::read(&path1).unwrap();
    let ct2 = std::fs::read(&path2).unwrap();
    assert_eq!(
        ct1, ct2,
        "Same plaintext + same salt+file_id must produce identical ciphertext"
    );

    decrypt_file(&path1, password).unwrap();
    assert_eq!(std::fs::read(&path1).unwrap(), plaintext);
}

#[test]
fn test_deterministic_encrypt_multi_chunk() {
    #[allow(clippy::cast_possible_truncation)]
    let plaintext = {
        let mut data = Vec::with_capacity(CHUNK_SIZE * 2 + 1000);
        for i in 0..(CHUNK_SIZE * 2 + 1000) {
            data.push(i as u8);
        }
        data
    };

    let password = b"test_password";
    let salt = [0x42; SALT_LEN];
    let file_id = [0x13; FILE_ID_LEN];
    let derived = derive_key(password, &salt).unwrap();
    let mut key = [0u8; 32];
    key.copy_from_slice(&*derived);

    let path1 = create_temp_file(&plaintext);
    let path2 = create_temp_file(&plaintext);

    encrypt_file(&path1, &key, &salt, Some(file_id), None).unwrap();
    encrypt_file(&path2, &key, &salt, Some(file_id), None).unwrap();

    let ct1 = std::fs::read(&path1).unwrap();
    let ct2 = std::fs::read(&path2).unwrap();
    assert_eq!(
        ct1, ct2,
        "Same multi-chunk plaintext + same salt+file_id must produce identical ciphertext"
    );

    decrypt_file(&path1, password).unwrap();
    assert_eq!(std::fs::read(&path1).unwrap(), plaintext);
}

#[test]
fn test_different_file_id_produces_different_ciphertext() {
    let plaintext = b"Same content, different file.";

    let password = b"test_password";
    let salt = [0x42; SALT_LEN];
    let derived = derive_key(password, &salt).unwrap();
    let mut key = [0u8; 32];
    key.copy_from_slice(&*derived);

    let path1 = create_temp_file(plaintext);
    let path2 = create_temp_file(plaintext);

    let file_id1 = [0x01; FILE_ID_LEN];
    let file_id2 = [0x02; FILE_ID_LEN];

    encrypt_file(&path1, &key, &salt, Some(file_id1), None).unwrap();
    encrypt_file(&path2, &key, &salt, Some(file_id2), None).unwrap();

    let ct1 = std::fs::read(&path1).unwrap();
    let ct2 = std::fs::read(&path2).unwrap();
    assert_ne!(
        ct1, ct2,
        "Same plaintext with different File_IDs must produce different ciphertext"
    );

    decrypt_file(&path1, password).unwrap();
    assert_eq!(std::fs::read(&path1).unwrap(), plaintext);
    decrypt_file(&path2, password).unwrap();
    assert_eq!(std::fs::read(&path2).unwrap(), plaintext);
}

#[cfg(unix)]
#[test]
fn test_metadata_preservation() {
    use std::os::unix::fs::PermissionsExt;

    let plaintext = b"Executable script content";
    let file = create_temp_file(plaintext);
    let path = file.path();

    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();

    let (key, salt) = get_test_key_and_salt();
    let master_key = b"super_secret_password";

    encrypt_file(path, &key, &salt, None, None).unwrap();

    let encrypted_perms = std::fs::metadata(path).unwrap().permissions();
    assert_eq!(encrypted_perms.mode() & 0o777, 0o755);

    let key_cache: KeyCache = DashMap::new();
    decrypt_file_with_cache(path, &key_cache, None, master_key).unwrap();

    let decrypted_perms = std::fs::metadata(path).unwrap().permissions();
    assert_eq!(decrypted_perms.mode() & 0o777, 0o755);
}

#[test]
fn test_empty_file_roundtrip() {
    let plaintext = b"";
    let path = create_temp_file(plaintext);

    let (key, salt) = get_test_key_and_salt();
    let master_key = b"super_secret_password";

    encrypt_file(&path, &key, &salt, None, None).unwrap();

    let enc = std::fs::read(&path).unwrap();
    assert_eq!(enc.len(), HEADER_LEN + NONCE_LEN + 16);

    decrypt_file(&path, master_key).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), plaintext);
}

#[test]
fn test_wrong_password_decrypt_fails() {
    let plaintext = b"data encrypted under one password";
    let path = create_temp_file(plaintext);

    let (key, salt) = get_test_key_and_salt();
    encrypt_file(&path, &key, &salt, None, None).unwrap();

    let result = decrypt_file(&path, b"a_completely_different_password");
    assert!(matches!(result, Err(crate::error::Error::DecryptFailed(_))));

    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(&bytes[..MAGIC.len()], MAGIC);
}

#[test]
fn test_truncated_ciphertext_after_nonce() {
    let plaintext = b"abc";
    let path = create_temp_file(plaintext);
    let (key, salt) = get_test_key_and_salt();
    encrypt_file(&path, &key, &salt, None, None).unwrap();

    let trunc_len = HEADER_LEN + NONCE_LEN;
    let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    f.set_len(trunc_len as u64).unwrap();
    drop(f);

    let result = decrypt_file(&path, b"super_secret_password");
    assert!(matches!(result, Err(crate::error::Error::TruncatedChunk)));
}

#[test]
fn test_truncated_before_first_nonce() {
    let path = create_temp_file(b"tiny");
    let key_cache: KeyCache = DashMap::new();
    let res = decrypt_file_with_cache(&path, &key_cache, None, b"any");
    assert!(res.is_ok());
    assert_eq!(std::fs::read(&path).unwrap(), b"tiny");
}

// --- Streaming Core Tests (encrypt_into / decrypt_into) ---

#[test]
fn test_stream_encrypt_decrypt_roundtrip() {
    let plaintext = b"streaming core roundtrip test data";
    let (key, salt) = get_test_key_and_salt();
    let master_key = b"super_secret_password";

    let mut reader = std::io::Cursor::new(plaintext.to_vec());
    let mut ciphertext = Vec::new();
    let header = encrypt_into(&mut reader, &mut ciphertext, &key, salt, None, None).unwrap();

    assert_eq!(&ciphertext[0..5], MAGIC);
    assert_eq!(ciphertext[5], VERSION);

    let mut enc_reader = std::io::Cursor::new(ciphertext.clone());
    let mut decrypted = Vec::new();
    let dec_header = decrypt_into(&mut enc_reader, &mut decrypted, master_key).unwrap();

    assert_eq!(decrypted, plaintext);
    assert_eq!(header.salt, dec_header.salt);
    assert_eq!(header.file_id, dec_header.file_id);
}

#[test]
fn test_stream_encrypt_with_compression() {
    let plaintext = b"X".repeat(50_000);
    let (key, salt) = get_test_key_and_salt();
    let master_key = b"super_secret_password";

    let mut reader = std::io::Cursor::new(plaintext.clone());
    let mut ciphertext = Vec::new();
    encrypt_into(&mut reader, &mut ciphertext, &key, salt, None, Some(3)).unwrap();

    assert!(ciphertext.len() < 5_000);

    let mut enc_reader = std::io::Cursor::new(ciphertext);
    let mut decrypted = Vec::new();
    decrypt_into(&mut enc_reader, &mut decrypted, master_key).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_stream_encrypt_deterministic_with_fixed_file_id() {
    let plaintext = b"deterministic stream test";
    let (key, salt) = get_test_key_and_salt();
    let file_id = [0x42; FILE_ID_LEN];

    let mut r1 = std::io::Cursor::new(plaintext.to_vec());
    let mut c1 = Vec::new();
    encrypt_into(&mut r1, &mut c1, &key, salt, Some(file_id), None).unwrap();

    let mut r2 = std::io::Cursor::new(plaintext.to_vec());
    let mut c2 = Vec::new();
    encrypt_into(&mut r2, &mut c2, &key, salt, Some(file_id), None).unwrap();

    assert_eq!(c1, c2, "Same plaintext + salt + file_id must be identical");
}

// --- File-to-File Tests (encrypt_file_to / decrypt_file_to) ---

#[test]
fn test_encrypt_file_to_different_destination() {
    let plaintext = b"file-to-file test data";
    let src = create_temp_file(plaintext);
    let dst_dir = tempfile::TempDir::new().unwrap();
    let dst = dst_dir.path().join("output.enc");

    let (key, salt) = get_test_key_and_salt();
    let master_key = b"super_secret_password";

    let header = encrypt_file_to(&src, &dst, &key, salt, None, None).unwrap();
    assert!(header.is_some());

    assert_eq!(std::fs::read(&src).unwrap(), plaintext);

    let enc = std::fs::read(&dst).unwrap();
    assert_eq!(&enc[0..5], MAGIC);

    let dst2 = dst_dir.path().join("output.dec");
    let result = decrypt_file_to(&dst, &dst2, master_key).unwrap();
    assert!(result.is_some());

    assert_eq!(std::fs::read(&dst2).unwrap(), plaintext);
}

#[test]
fn test_encrypt_file_to_creates_parent_dirs() {
    let plaintext = b"nested dir test";
    let src = create_temp_file(plaintext);
    let dst_dir = tempfile::TempDir::new().unwrap();
    let dst = dst_dir.path().join("a/b/c/output.enc");

    let (key, salt) = get_test_key_and_salt();
    encrypt_file_to(&src, &dst, &key, salt, None, None).unwrap();

    assert!(dst.exists());
    assert_eq!(&std::fs::read(&dst).unwrap()[0..5], MAGIC);
}

#[test]
fn test_decrypt_file_to_skips_non_encrypted() {
    let src = create_temp_file(b"just plaintext, no encryption");
    let dst_dir = tempfile::TempDir::new().unwrap();
    let dst = dst_dir.path().join("out.txt");

    let result = decrypt_file_to(&src, &dst, b"any_key").unwrap();
    assert!(result.is_none(), "Should skip non-encrypted file");
    assert!(!dst.exists(), "Destination should not be created");
}

#[test]
fn test_encrypt_file_to_skips_already_encrypted() {
    let plaintext = b"already encrypted source";
    let (key, salt) = get_test_key_and_salt();

    let src = create_temp_file(plaintext);
    encrypt_file(&src, &key, &salt, None, None).unwrap();
    assert_eq!(&std::fs::read(&src).unwrap()[0..5], MAGIC);

    let dst_dir = tempfile::TempDir::new().unwrap();
    let dst = dst_dir.path().join("out2.enc");
    let result = encrypt_file_to(&src, &dst, &key, salt, None, None).unwrap();
    assert!(result.is_none(), "Should skip already-encrypted source");
    assert!(!dst.exists());
}

#[test]
fn test_encrypt_file_to_in_place_matches_encrypt_file() {
    let plaintext = b"in-place compatibility test";
    let (key, salt) = get_test_key_and_salt();

    let p1 = create_temp_file(plaintext);
    encrypt_file(&p1, &key, &salt, Some([0xAA; FILE_ID_LEN]), None).unwrap();

    let p2 = create_temp_file(plaintext);
    encrypt_file_to(&p2, &p2, &key, salt, Some([0xAA; FILE_ID_LEN]), None).unwrap();

    assert_eq!(std::fs::read(&p1).unwrap(), std::fs::read(&p2).unwrap());
}

// --- Batch API Tests ---

#[test]
fn test_decrypt_files_to_batch() {
    let master_key = b"batch_password";
    let (key, salt) = {
        let password = master_key;
        let mut s = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut s);
        let derived = derive_key(password, &s).unwrap();
        let mut k = [0u8; 32];
        k.copy_from_slice(&*derived);
        (k, s)
    };

    let temp_paths: Vec<TempPath> = (0..3)
        .map(|i| {
            let path = create_temp_file(format!("batch item {i}").as_bytes());
            encrypt_file(&path, &key, &salt, None, None).unwrap();
            path
        })
        .collect();
    let sources: Vec<PathBuf> = temp_paths.iter().map(PathBuf::from).collect();

    let out_dir = tempfile::TempDir::new().unwrap();
    let summary = decrypt_files_to(&sources, master_key, |src: &Path| {
        Some(out_dir.path().join(src.file_name().unwrap()))
    })
    .unwrap();

    assert_eq!(summary.total, 3);
    assert_eq!(summary.succeeded, 3);
    assert_eq!(summary.skipped, 0);
    assert_eq!(summary.failed, 0);
    assert!(summary.is_ok());

    for (i, src) in sources.iter().enumerate() {
        let dec_path = out_dir.path().join(src.file_name().unwrap());
        assert_eq!(
            std::fs::read(&dec_path).unwrap(),
            format!("batch item {i}").as_bytes()
        );
    }
}

#[test]
fn test_decrypt_files_to_skips_non_encrypted() {
    let temp_paths: Vec<TempPath> = (0..3)
        .map(|i| create_temp_file(format!("plaintext {i}").as_bytes()))
        .collect();
    let sources: Vec<PathBuf> = temp_paths.iter().map(PathBuf::from).collect();

    let out_dir = tempfile::TempDir::new().unwrap();
    let summary = decrypt_files_to(&sources, b"any", |src: &Path| {
        Some(out_dir.path().join(src.file_name().unwrap()))
    })
    .unwrap();

    assert_eq!(summary.total, 3);
    assert_eq!(summary.succeeded, 0);
    assert_eq!(summary.skipped, 3);
    assert_eq!(summary.failed, 0);
}

#[test]
fn test_decrypt_files_to_mapper_skip() {
    let master_key = b"batch_password";
    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    let derived = derive_key(master_key, &salt).unwrap();
    let mut key = [0u8; 32];
    key.copy_from_slice(&*derived);

    let temp_paths: Vec<TempPath> = (0..3)
        .map(|i| {
            let path = create_temp_file(format!("item {i}").as_bytes());
            encrypt_file(&path, &key, &salt, None, None).unwrap();
            path
        })
        .collect();
    let sources: Vec<PathBuf> = temp_paths.iter().map(PathBuf::from).collect();

    let out_dir = tempfile::TempDir::new().unwrap();
    let skip_path = sources[1].clone();
    let summary = decrypt_files_to(&sources, master_key, |src: &Path| {
        if src == skip_path.as_path() {
            None
        } else {
            Some(out_dir.path().join(src.file_name().unwrap()))
        }
    })
    .unwrap();

    assert_eq!(summary.succeeded, 2);
    assert!(summary.is_ok());
}

#[test]
fn test_encrypt_files_to_batch() {
    let master_key = b"batch_encrypt_password";

    let temp_paths: Vec<TempPath> = (0..3)
        .map(|i| create_temp_file(format!("source item {i}").as_bytes()))
        .collect();
    let sources: Vec<PathBuf> = temp_paths.iter().map(PathBuf::from).collect();

    let out_dir = tempfile::TempDir::new().unwrap();
    let summary = encrypt_files_to(
        &sources,
        master_key,
        |src: &Path| Some(out_dir.path().join(src.file_name().unwrap())),
        None,
    )
    .unwrap();

    assert_eq!(summary.total, 3);
    assert_eq!(summary.succeeded, 3);
    assert_eq!(summary.failed, 0);
    assert!(summary.is_ok());

    for (i, src) in sources.iter().enumerate() {
        let enc_path = out_dir.path().join(src.file_name().unwrap());
        let enc = std::fs::read(&enc_path).unwrap();
        assert_eq!(&enc[0..5], MAGIC);

        let dec_path = out_dir.path().join(format!("dec_{i}"));
        decrypt_file_to(&enc_path, &dec_path, master_key).unwrap();
        assert_eq!(
            std::fs::read(&dec_path).unwrap(),
            format!("source item {i}").as_bytes()
        );
    }
}

#[test]
fn test_encrypt_files_to_with_compression() {
    let master_key = b"batch_compress_password";

    let temp_path = create_temp_file(&b"Z".repeat(30_000));
    let sources: Vec<PathBuf> = vec![temp_path.to_path_buf()];

    let out_dir = tempfile::TempDir::new().unwrap();
    let summary = encrypt_files_to(
        &sources,
        master_key,
        |src: &Path| Some(out_dir.path().join(src.file_name().unwrap())),
        Some(15),
    )
    .unwrap();

    assert_eq!(summary.succeeded, 1);

    let enc_path = out_dir.path().join(sources[0].file_name().unwrap());
    assert!(std::fs::metadata(&enc_path).unwrap().len() < 5_000);
}
