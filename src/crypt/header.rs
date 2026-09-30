// GITSE Binary Header Layout (64 Bytes)
//  00          04  05  06  07           17                  27              3F
//  +-----------+---+---+---+-----------+-------------------+---------------+
//  |   MAGIC   | V | F | A |   SALT    |     `FILE_ID`     |   RESERVED    |
//  |  "GITSE"  |   |   |   | (16 bytes)|    (16 bytes)     |  (24 bytes)   |
//  +-----------+---+---+---+-----------+-------------------+---------------+
//    5 bytes     1   1   1    16 bytes       16 bytes          24 bytes
//                |   |   |
//     Version ---+   |   +--- Encryption Algo (1 = XChaCha20-Poly1305 Stream)
//                    |
//      Flags --------+ (Bit 0: Compression)

use rand::Rng;

pub const MAGIC: &[u8; 5] = b"GITSE";
pub const VERSION: u8 = 3;
pub(super) const FLAG_COMPRESSED: u8 = 1 << 0;
pub(super) const ENC_ALGO: u8 = 1;

pub const SALT_LEN: usize = 16;
pub const FILE_ID_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const HEADER_LEN: usize = 64;
pub(super) const RESERVED_LEN: usize =
    HEADER_LEN - (MAGIC.len() + 1 + 1 + 1 + SALT_LEN + FILE_ID_LEN);

pub const CHUNK_SIZE: usize = 65536;

#[inline]
#[must_use]
pub const fn is_encrypted_version(v: u8) -> bool {
    v == VERSION
}

/// Read exactly [`HEADER_LEN`] raw bytes from `reader` for sniffing.
///
/// `Ok(None)` means the stream ended before the header finished — too short
/// to be an encrypted file. Other IO errors propagate. Shared by the
/// encrypt/decrypt pre-reads and `utils::is_file_encrypted`.
pub fn read_header_bytes<R: std::io::Read>(
    reader: &mut R,
) -> crate::error::Result<Option<[u8; HEADER_LEN]>> {
    let mut buf = [0u8; HEADER_LEN];
    match reader.read_exact(&mut buf) {
        Ok(()) => Ok(Some(buf)),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Sniff-level check on raw header bytes: do they carry our magic and a
/// version we can decrypt? (Full validation, including `enc_algo`, happens in
/// [`FileHeader::from_bytes`].)
#[must_use]
pub fn is_encrypted_header(bytes: &[u8; HEADER_LEN]) -> bool {
    &bytes[0..5] == MAGIC && is_encrypted_version(bytes[5])
}

/// Sniff-level check on raw header bytes: do they carry our magic?
///
/// Magic alone means "this file claims to be a GITSE product" — the right
/// gate for *skip/leave-untouched* decisions (re-encrypting over it would
/// double-wrap data from another format version), as opposed to
/// *can-we-decrypt* decisions, which need [`sniff`] or [`FileHeader::from_bytes`].
#[must_use]
pub fn has_gitse_magic(bytes: &[u8; HEADER_LEN]) -> bool {
    &bytes[0..5] == MAGIC
}

/// Sniff classification of a raw 64-byte header prefix.
///
/// Splits "carries our magic" from "we fully understand it", so callers never
/// silently double-encrypt a foreign-version file nor silently treat one of
/// our own files as plaintext.
pub enum Sniffed {
    /// No GITSE magic — ordinary plaintext.
    Plaintext,
    /// Fully recognized: supported version and known algorithm.
    Ciphertext,
    /// GITSE magic but a version this build cannot handle (future format).
    /// Never encrypt over it; decrypting it is impossible.
    FutureVersion(u8),
    /// GITSE magic, supported version, but an unknown algorithm byte — almost
    /// certainly a plaintext imitating our header. Safe to encrypt as-is.
    UnknownAlgo(u8),
}

/// Classify raw header bytes (see [`Sniffed`]).
pub fn sniff(bytes: &[u8; HEADER_LEN]) -> Sniffed {
    if !has_gitse_magic(bytes) {
        return Sniffed::Plaintext;
    }
    if !is_encrypted_version(bytes[5]) {
        return Sniffed::FutureVersion(bytes[5]);
    }
    if bytes[7] != ENC_ALGO {
        return Sniffed::UnknownAlgo(bytes[7]);
    }
    Sniffed::Ciphertext
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileHeader {
    pub magic: [u8; 5],
    pub version: u8,
    pub flags: u8,
    pub enc_algo: u8,
    pub salt: [u8; SALT_LEN],
    pub file_id: [u8; FILE_ID_LEN],
    pub reserved: [u8; RESERVED_LEN],
}

const _: () = assert!(size_of::<FileHeader>() == HEADER_LEN);
const _: () = assert!(align_of::<FileHeader>() == 1);

impl FileHeader {
    #[must_use]
    pub const fn new(compressed: bool, salt: [u8; SALT_LEN], file_id: [u8; FILE_ID_LEN]) -> Self {
        let mut flags = 0u8;
        if compressed {
            flags |= FLAG_COMPRESSED;
        }
        Self {
            magic: *MAGIC,
            version: VERSION,
            flags,
            enc_algo: ENC_ALGO,
            salt,
            file_id,
            reserved: [0u8; RESERVED_LEN],
        }
    }

    #[must_use]
    pub fn generate_file_id() -> [u8; FILE_ID_LEN] {
        let mut rng = rand::rng();
        let mut id = [0u8; FILE_ID_LEN];
        rng.fill_bytes(&mut id);
        id
    }

    pub fn from_bytes(bytes: &[u8; HEADER_LEN]) -> crate::error::Result<&Self> {
        use crate::error::Error;

        let header: &Self = unsafe { &*(bytes.as_ptr().cast()) };

        if &header.magic != MAGIC {
            return Err(Error::InvalidMagic);
        }
        if !is_encrypted_version(header.version) {
            return Err(Error::UnsupportedVersion(header.version));
        }
        if header.enc_algo != ENC_ALGO {
            return Err(Error::UnsupportedAlgo(header.enc_algo));
        }

        Ok(header)
    }

    pub fn read_from<R: std::io::Read>(reader: &mut R) -> crate::error::Result<Self> {
        let mut buf = [0u8; HEADER_LEN];
        reader.read_exact(&mut buf)?;
        Ok(*Self::from_bytes(&buf)?)
    }

    pub fn write_to<W: std::io::Write>(&self, writer: &mut W) -> crate::error::Result<()> {
        writer.write_all(self.as_bytes())?;
        Ok(())
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HEADER_LEN] {
        unsafe { &*std::ptr::from_ref::<Self>(self).cast() }
    }

    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        (self.flags & FLAG_COMPRESSED) != 0
    }
}
