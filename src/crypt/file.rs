use std::{
    fs,
    io::{Seek, SeekFrom},
    path::Path,
};

use chacha20poly1305_simd::XChaCha20Poly1305;
use log::{debug, warn};
use tempfile::NamedTempFile;

use crate::{
    crypt::{
        header::{FILE_ID_LEN, FileHeader, SALT_LEN, has_gitse_magic, read_header_bytes},
        key::{KeyCache, KeyDerivation, split_key_enc},
        stream::{decrypt_body, encrypt_into},
    },
    error::{Error, Result},
    salt_cache::{CacheRef, CachedEntry},
};

/// Persist a `NamedTempFile` to `dst` atomically, optionally copying metadata.
pub(super) fn persist_temp_file(
    temp_file: NamedTempFile,
    dst: &Path,
    metadata_source: Option<&Path>,
) -> Result<()> {
    if let Some(src) = metadata_source
        && let Err(e) = copy_metadata::copy_metadata(src, temp_file.path())
    {
        warn!("Could not copy metadata from {}: {}", src.display(), e);
    }
    temp_file
        .persist(dst)
        .map_err(|e| Error::AtomicPersist(dst.to_path_buf(), e.to_string()))?;
    Ok(())
}

/// Encrypt `src` into `dst`.
pub fn encrypt_file_to(
    src: &Path,
    dst: &Path,
    derived_key: &[u8; 32],
    salt: [u8; SALT_LEN],
    file_id: Option<[u8; FILE_ID_LEN]>,
    zstd: Option<u8>,
) -> Result<Option<FileHeader>> {
    let mut src_file = fs::File::open(src)?;

    // Magic-only skip: a GITSE file of ANY version is one of ours —
    // re-encrypting it would double-wrap data (needing two decrypts), so it
    // is left untouched regardless of whether this build understands it.
    if let Some(bytes) = read_header_bytes(&mut src_file)?
        && has_gitse_magic(&bytes)
    {
        warn!("Source file already encrypted, skipping: {}", src.display());
        return Ok(None);
    }
    src_file.seek(SeekFrom::Start(0))?;

    debug!("Encrypting {} → {}", src.display(), dst.display());

    let dst_parent = dst.parent().unwrap_or_else(|| Path::new("."));
    // Skip the stat+mkdir round-trip when the destination already lives in a
    // directory the source is in (the in-place path, or same-dir writes) —
    // that directory necessarily exists.
    // Literal comparison only: semantically-equal spellings (trailing slash,
    // `..`, case on Windows) just cost one extra mkdir; harmless.
    let src_parent = src.parent().unwrap_or_else(|| Path::new("."));
    if src_parent != dst_parent {
        fs::create_dir_all(dst_parent)?;
    }
    let mut temp_file = NamedTempFile::new_in(dst_parent)?;

    let header = encrypt_into(
        &mut src_file,
        &mut temp_file,
        derived_key,
        salt,
        file_id,
        zstd,
    )?;

    drop(src_file);
    persist_temp_file(temp_file, dst, Some(src))?;

    Ok(Some(header))
}

/// Decrypt `src` into `dst` — the single implementation behind every
/// decrypt entry point (public wrappers, batch, and repo paths).
///
/// Caller-specific differences are parameterized:
/// - `derivation`: fresh Argon2 per call vs deduplicated via a shared [`KeyCache`];
/// - `salt_cache`: optionally record `(salt, file_id)` for deterministic re-encryption.
///
/// Returns `Ok(None)` when `src` is not encrypted by this tool (too short or
/// no GITSE magic), so callers can tell skip from failure without a separate
/// header pre-read. A file carrying the magic but an unsupported
/// version/algorithm fails with an explicit error instead.
pub(super) fn decrypt_file_impl(
    src: &Path,
    dst: &Path,
    master_key: &[u8],
    derivation: KeyDerivation<'_>,
    salt_cache: Option<CacheRef<'_>>,
) -> Result<Option<FileHeader>> {
    let mut src_file = fs::File::open(src)?;

    let Some(header_bytes) = read_header_bytes(&mut src_file)? else {
        debug!(
            "File too small to be encrypted, skipping: {}",
            src.display()
        );
        return Ok(None);
    };
    if !has_gitse_magic(&header_bytes) {
        debug!("File not encrypted (no magic), skipping: {}", src.display());
        return Ok(None);
    }

    debug!("Decrypting {} → {}", src.display(), dst.display());
    // Magic without a supported version/algorithm is OUR file this build
    // cannot handle — `from_bytes` turns that into an explicit error
    // (`UnsupportedVersion` / `UnsupportedAlgo`) instead of letting the
    // caller silently treat the ciphertext as plaintext.
    let header = *FileHeader::from_bytes(&header_bytes)?;

    // Record (salt, file_id) before decryption: even if the body fails to
    // decrypt, the entry matches the on-disk header, so persisting early is
    // harmless and preserves partial progress.
    if let Some(cache) = salt_cache {
        cache.sender.insert(cache.key, CachedEntry {
            salt: header.salt,
            file_id: header.file_id,
        });
    }

    let derived_key = derivation.derive(master_key, &header.salt)?;
    let key_enc = split_key_enc(&derived_key);
    let cipher = XChaCha20Poly1305::new(*key_enc);

    let dst_parent = dst.parent().unwrap_or_else(|| Path::new("."));
    // See encrypt_file_to: skip mkdir when src and dst share a parent.
    let src_parent = src.parent().unwrap_or_else(|| Path::new("."));
    if src_parent != dst_parent {
        fs::create_dir_all(dst_parent)?;
    }
    let mut temp_file = NamedTempFile::new_in(dst_parent)?;

    decrypt_body(&mut src_file, &mut temp_file, &cipher, &header)?;

    drop(src_file);
    persist_temp_file(temp_file, dst, Some(src))?;

    Ok(Some(header))
}

/// Decrypt `src` into `dst`.
pub fn decrypt_file_to(src: &Path, dst: &Path, master_key: &[u8]) -> Result<Option<FileHeader>> {
    decrypt_file_impl(src, dst, master_key, KeyDerivation::Direct, None)
}

/// Encrypt a single file **in place**.
pub fn encrypt_file(
    path: &Path,
    derived_key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    file_id: Option<[u8; FILE_ID_LEN]>,
    zstd: Option<u8>,
) -> Result<Option<FileHeader>> {
    encrypt_file_to(path, path, derived_key, *salt, file_id, zstd)
}

/// Decrypt a single file **in place**.
pub fn decrypt_file(path: &Path, master_key: &[u8]) -> Result<()> {
    decrypt_file_to(path, path, master_key).map(|_| ())
}

/// Decrypt a single file **in place** with a thread-safe Argon2 key cache and
/// optional salt/`file_id` cache.
pub fn decrypt_file_with_cache(
    path: &Path,
    key_cache: &KeyCache,
    cache: Option<CacheRef<'_>>,
    master_key: &[u8],
) -> Result<()> {
    decrypt_file_impl(
        path,
        path,
        master_key,
        KeyDerivation::Shared(key_cache),
        cache,
    )
    .map(|_| ())
}
