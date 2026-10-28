//! cargo-fuzz support surface: public drivers over crate-internal engines so
//! fuzz targets exercise the real production code paths without widening the
//! shipped API. Compiled only under `cfg(fuzzing)` (set by cargo-fuzz).

use std::{
    io::{Read, Write},
    sync::OnceLock,
};

use dashmap::DashMap;

use crate::{
    crypt::{HEADER_LEN, MAGIC, SALT_LEN},
    error::Result,
    repo::Repo,
};

/// A reusable host for the process filter protocol: one password fetch, one
/// Argon2 key cache and one salt-cache snapshot amortized across every
/// session served from it.
pub struct FilterProcessSession<'a> {
    ctx: crate::filter::FilterContext<'a>,
    repo: &'a Repo,
}

impl<'a> FilterProcessSession<'a> {
    #[must_use]
    pub fn new(repo: &'a Repo) -> Self {
        Self {
            ctx: crate::filter::FilterContext::new(repo, crate::filter::SaltSource::Process),
            repo,
        }
    }

    /// The repo the sessions are served against.
    #[must_use]
    pub fn repo(&self) -> &'a Repo {
        self.repo
    }

    /// Serve one full protocol session: `input` is the raw client byte
    /// stream, response bytes land in `output`. Protocol violations return
    /// `Err`; a panic is always a bug.
    pub fn serve(&self, input: &mut dyn Read, output: &mut dyn Write) -> Result<()> {
        crate::filter::process::run_session(&self.ctx, input, output)
    }
}

/// Process-wide key cache for the fuzz targets: one Argon2 run per salt per
/// fuzzing process, shared by every target via `KeyDerivation::Shared`.
#[must_use]
pub fn key_cache() -> &'static crate::crypt::KeyCache {
    static CACHE: OnceLock<crate::crypt::KeyCache> = OnceLock::new();
    CACHE.get_or_init(DashMap::new)
}

/// Overwrite the salt field of every embedded GITSE header with `salt`.
///
/// Fuzz-support helper: the salt carries no parsing logic, and a fixed salt
/// keeps the Argon2 derivation cached across the whole run instead of one
/// derivation per random salt.
pub fn normalize_header_salts(bytes: &mut [u8], salt: [u8; SALT_LEN]) {
    let mut i = 0;
    while i + 5 + 3 + SALT_LEN <= bytes.len() {
        if bytes[i..i + MAGIC.len()] == *MAGIC {
            bytes[i + 7..i + 7 + SALT_LEN].copy_from_slice(&salt);
            i += HEADER_LEN;
        } else {
            i += 1;
        }
    }
}
