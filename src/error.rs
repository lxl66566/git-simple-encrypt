//! Crate-wide error type.
//!
//! Library code returns [`Error`] (typed via `thiserror`) so downstream users
//! can match on error kinds. Internal helpers use other dedicated variants;
//! [`Error::Other`] serves as a catch-all for opaque error messages from the
//! binary layer (git config, path absolutization, etc.).

use std::path::PathBuf;

use thiserror::Error;

/// The error type returned by all public library functions.
#[derive(Debug, Error)]
pub enum Error {
    /// `repo` argument was not an absolute path (lib callers must absolutize).
    #[error("repository path must be absolute: {0}")]
    RepoPathNotAbsolute(PathBuf),

    /// Repository directory does not exist.
    #[error("repo not found: {0}")]
    RepoNotFound(PathBuf),

    /// Repository path is not a directory.
    #[error("not a directory: {0}")]
    NotADirectory(PathBuf),

    /// Path supplied for the crypt list does not exist on disk.
    #[error("file or directory does not exist: {0}")]
    PathNotExist(PathBuf),

    /// Expected a repo-relative path but got an absolute one.
    #[error("expected repo-relative path, got absolute: {0}")]
    PathNotRelative(PathBuf),

    /// Master key/password is empty.
    #[error("key must not be empty")]
    EmptyKey,

    /// User entered an empty password interactively.
    #[error("password must not be empty")]
    EmptyPassword,

    /// Operation had no target files to act on.
    #[error("no file to {0}")]
    NoFile(&'static str),

    /// File does not start with the `GITSE` magic / supported version.
    #[error("invalid magic bytes")]
    InvalidMagic,

    /// Header advertises an unsupported format version.
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),

    /// Header advertises an unsupported encryption algorithm.
    #[error("unsupported encryption algorithm: {0}")]
    UnsupportedAlgo(u8),

    /// Header could not be parsed / validated.
    #[error("corrupt header in {0}")]
    CorruptHeader(PathBuf),

    /// XChaCha20-Poly1305 encryption failure.
    #[error("encryption failed: {0}")]
    EncryptFailed(String),

    /// XChaCha20-Poly1305 decryption failure (wrong password, corrupt or
    /// tampered data are all reported identically by AEAD).
    #[error("decryption failed (wrong password, corrupt, or tampered data): {0}")]
    DecryptFailed(String),

    /// Argon2 key derivation failure.
    #[error("Argon2 key derivation failed: {0}")]
    Argon2(String),

    /// Encrypted chunk is missing its ciphertext.
    #[error("truncated chunk: nonce present but no ciphertext follows")]
    TruncatedChunk,

    /// Encrypted file ended without a final chunk.
    #[error("file truncation detected! the ciphertext is incomplete")]
    FileTruncated,

    /// Atomic temp-file persist failed.
    #[error("failed to persist atomic write to {0}: {1}")]
    AtomicPersist(PathBuf, String),

    /// Underlying `git` invocation failed.
    #[error("git command failed: {0}")]
    Git(String),

    /// A pre-commit hook already exists at the target path.
    #[error("a pre-commit hook already exists at {0}; remove it manually before installing")]
    HookExists(PathBuf),

    /// `check` found unencrypted files. The count is `(unencrypted, total)`.
    #[error("{0} out of {1} files are not encrypted")]
    FilesNotEncrypted(usize, usize),

    /// Config file parse/serialize error.
    #[error("config error: {0}")]
    Config(String),

    /// Generic I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Rkyv (de)serialization failure for the salt cache.
    #[error("salt cache serialization error: {0}")]
    SaltCache(String),

    /// Anything else — an opaque error message.
    #[error("{0}")]
    Other(String),
}

/// Convenience alias used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;
