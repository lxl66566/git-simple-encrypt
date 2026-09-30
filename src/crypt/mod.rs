//! The core of this program. Encrypt/decrypt, compress/decompress files.
//!
//! # Module Structure
//!
//! | Module | Contents |
//! |---|---|
//! | [`header`] | Constants (`MAGIC`, `VERSION`, `SALT_LEN`, …) and [`FileHeader`] |
//! | [`key`] | Key derivation (Argon2, key splitting, nonce derivation) + key cache |
//! | [`stream`] | Streaming `Read → Write` encrypt/decrypt primitives |
//! | [`file`] | File-to-file encrypt/decrypt with atomic writes & metadata preservation |
//! | [`batch`] | Parallel batch operations with shared key cache; also hosts the tallying engine reused by `encrypt_repo`/`decrypt_repo` |
//! | [`repo`] | Repository-level encrypt/decrypt with salt cache integration |
//!
//! See the module-level docs of each submodule for details.
//!
//! # Nonce Derivation (Content-Based with File ID)
//!
//! Per-chunk nonces are derived from the file's random `File_ID` and the
//! chunk's own plaintext content using keyed Blake3:
//!
//! 1. A random 16-byte `File_ID` is generated once per file and stored in the header. This ensures
//!    that even if two different files have identical plaintext at chunk 0, they produce different
//!    nonces and ciphertexts.
//! 2. The Argon2-derived master key is split via `blake3::derive_key` into `Key_ENC` (for
//!    XChaCha20-Poly1305 encryption) and `Key_MAC` (for nonce generation).
//! 3. For each chunk `i`: `Nonce_i = Blake3_keyed(Key_MAC, File_ID || M_i || chunk_idx_le)[0..24]`
//! 4. The 24-byte nonce is stored in plaintext at the head of each encrypted chunk.
//!
//! Different plaintext always produces a different nonce (within the same
//! file). The `File_ID` ensures cross-file uniqueness. The chunk index prevents
//! reordering attacks on identical 64 KB blocks.
//!
//! # Authenticated Additional Data (AAD)
//!
//! Each chunk's AAD binds the ciphertext to the full file header so that any
//! tampering with header fields (version, compression flag, salt, `file_id`,
//! reserved) is detected via Poly1305 authentication failure:
//!
//! ```text
//! AAD = HEADER (64B) || chunk_idx (8B LE) || is_last_chunk (1B)   // 73 bytes
//! ```
//!
//! Each encrypted chunk layout: `[NONCE (24B)] [CIPHERTEXT] [TAG (16B)]`

pub mod batch;
mod file;
mod header;
mod key;
mod repo;
mod stream;

pub use batch::BatchSummary;
pub use file::{
    decrypt_file, decrypt_file_to, decrypt_file_with_cache, encrypt_file, encrypt_file_to,
};
pub use header::{
    CHUNK_SIZE, FILE_ID_LEN, FileHeader, HEADER_LEN, MAGIC, NONCE_LEN, SALT_LEN, VERSION,
    is_encrypted_version,
};
// Sniff helpers shared with `utils::is_file_encrypted`, the file pre-reads and
// the git filter; crate-internal to avoid growing the public API.
pub(crate) use header::{Sniffed, is_encrypted_header, read_header_bytes, sniff};
pub use key::derive_key;
pub use repo::{cache_key, decrypt_repo, encrypt_repo};
pub use stream::{decrypt_into, encrypt_into};

#[cfg(test)]
mod tests;
