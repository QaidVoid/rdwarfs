//! Section header (64 bytes) parser and writer.
//!
//! Byte layout from `doc/dwarfs-format.md` (MIT):
//!
//! ```text
//! 0x00..0x06   magic "DWARFS"
//! 0x06         major version (u8)
//! 0x07         minor version (u8)
//! 0x08..0x28   SHA-512/256 over bytes >= 0x28
//! 0x28..0x30   XXH3-64 (u64 LE) over bytes >= 0x30
//! 0x30..0x34   section number (u32 LE)
//! 0x34..0x36   section type (u16 LE)
//! 0x36..0x38   compression algorithm (u16 LE)
//! 0x38..0x40   payload length (u64 LE)
//! 0x40..       payload
//! ```

use crate::Error;
use crate::format::types::{Compression, SectionType};

/// On-disk magic for every section header.
pub const MAGIC: [u8; 6] = *b"DWARFS";

/// Format version this build supports.
pub const SUPPORTED_MAJOR: u8 = 2;
/// Highest minor version this build accepts when reading.
///
/// The format spec states that v0.16.0 of the reference implementation
/// will start writing minor version 6, and that a reader accepts any
/// minor version up to the highest it knows. Accepting 6 ahead of time
/// means images from that release stay readable here.
pub const SUPPORTED_MINOR: u8 = 6;

/// Minor version this build writes.
///
/// Deliberately behind [`SUPPORTED_MINOR`]: the spec separates the
/// accepted version from the written one so a writer does not lock out
/// readers that predate the bump. Raise this only once writing 6 is
/// what the format actually calls for.
pub const WRITTEN_MINOR: u8 = 5;

/// Size of a section header in bytes.
pub const HEADER_LEN: usize = 64;

/// Byte offset where the SHA-512/256 hash coverage begins.
pub const SHA_COVER_START: usize = 0x28;
/// Byte offset where the XXH3-64 hash coverage begins.
pub const XXH_COVER_START: usize = 0x30;

/// A parsed section header. Fields are exactly the bytes recorded in
/// the image; integrity hashes are validated separately.
#[derive(Debug, Clone, Copy)]
pub struct SectionHeader {
    /// Format major version. Major mismatch is unsupported.
    pub major: u8,
    /// Format minor version. Newer minors may be rejected per spec.
    pub minor: u8,
    /// SHA-512/256 over bytes from offset 0x28 to the end of the
    /// payload.
    pub sha512_256: [u8; 32],
    /// XXH3-64 (little-endian u64) over bytes from offset 0x30 to the
    /// end of the payload.
    pub xxh3_64: u64,
    /// Monotonically increasing section number assigned by the writer.
    pub number: u32,
    /// Section type.
    pub section_type: SectionType,
    /// Compression algorithm applied to the payload.
    pub compression: Compression,
    /// Length of the payload immediately following the header.
    pub payload_len: u64,
}

impl SectionHeader {
    /// Parse a header from a 64-byte slice.
    ///
    /// `offset` is the byte position in the source image where the
    /// header begins; it is only used to enrich errors.
    pub fn parse(bytes: &[u8], offset: u64) -> Result<Self, Error> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::TruncatedHeader { offset });
        }

        if bytes[0..6] != MAGIC {
            return Err(Error::BadMagic { offset });
        }

        let major = bytes[6];
        let minor = bytes[7];

        if major != SUPPORTED_MAJOR || minor > SUPPORTED_MINOR {
            return Err(Error::UnsupportedVersion { major, minor });
        }

        let mut sha512_256 = [0u8; 32];
        sha512_256.copy_from_slice(&bytes[0x08..0x28]);

        let xxh3_64 = u64::from_le_bytes(bytes[0x28..0x30].try_into().unwrap());
        let number = u32::from_le_bytes(bytes[0x30..0x34].try_into().unwrap());
        let st_raw = u16::from_le_bytes(bytes[0x34..0x36].try_into().unwrap());
        let cp_raw = u16::from_le_bytes(bytes[0x36..0x38].try_into().unwrap());
        let payload_len = u64::from_le_bytes(bytes[0x38..0x40].try_into().unwrap());

        let section_type = SectionType::from_u16(st_raw);
        let compression = Compression::from_u16(cp_raw);

        Ok(Self {
            major,
            minor,
            sha512_256,
            xxh3_64,
            number,
            section_type,
            compression,
            payload_len,
        })
    }

    /// Total length of this section on disk (header + payload).
    /// Returns `u64::MAX` if `HEADER_LEN + payload_len` would
    /// overflow; callers chain through `checked_add` to surface the
    /// out-of-bounds case as a parse error instead of a panic.
    pub fn section_len(&self) -> u64 {
        (HEADER_LEN as u64).saturating_add(self.payload_len)
    }

    /// Serialize this header back to its 64-byte on-disk form. Used by
    /// tests and the eventual writer; hashes and version fields are
    /// written verbatim.
    pub fn write(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0..6].copy_from_slice(&MAGIC);
        buf[6] = self.major;
        buf[7] = self.minor;
        buf[0x08..0x28].copy_from_slice(&self.sha512_256);
        buf[0x28..0x30].copy_from_slice(&self.xxh3_64.to_le_bytes());
        buf[0x30..0x34].copy_from_slice(&self.number.to_le_bytes());
        buf[0x34..0x36].copy_from_slice(&self.section_type.as_u16().to_le_bytes());
        buf[0x36..0x38].copy_from_slice(&self.compression.as_u16().to_le_bytes());
        buf[0x38..0x40].copy_from_slice(&self.payload_len.to_le_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SectionHeader {
        SectionHeader {
            major: 2,
            minor: 5,
            sha512_256: [0xAB; 32],
            xxh3_64: 0x0123_4567_89AB_CDEF,
            number: 7,
            section_type: SectionType::MetadataV2,
            compression: Compression::Zstd,
            payload_len: 1024,
        }
    }

    #[test]
    fn roundtrip() {
        let h = sample();
        let bytes = h.write();
        let parsed = SectionHeader::parse(&bytes, 0).unwrap();
        assert_eq!(parsed.major, 2);
        assert_eq!(parsed.minor, 5);
        assert_eq!(parsed.sha512_256, h.sha512_256);
        assert_eq!(parsed.xxh3_64, h.xxh3_64);
        assert_eq!(parsed.number, h.number);
        assert_eq!(parsed.section_type, h.section_type);
        assert_eq!(parsed.compression, h.compression);
        assert_eq!(parsed.payload_len, h.payload_len);
        assert_eq!(parsed.section_len(), 64 + 1024);
    }

    #[test]
    fn rejects_short_input() {
        let bytes = [0u8; 32];
        let err = SectionHeader::parse(&bytes, 0x1000).unwrap_err();
        assert!(matches!(err, Error::TruncatedHeader { offset: 0x1000 }));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = sample().write();
        bytes[0] = b'X';
        let err = SectionHeader::parse(&bytes, 42).unwrap_err();
        assert!(matches!(err, Error::BadMagic { offset: 42 }));
    }

    #[test]
    fn rejects_unsupported_major() {
        let mut h = sample();
        h.major = 3;
        let bytes = h.write();
        let err = SectionHeader::parse(&bytes, 0).unwrap_err();
        assert!(matches!(
            err,
            Error::UnsupportedVersion { major: 3, minor: 5 }
        ));
    }

    #[test]
    fn accepts_every_supported_minor() {
        for minor in 0..=SUPPORTED_MINOR {
            let mut h = sample();
            h.minor = minor;
            let bytes = h.write();
            let parsed = SectionHeader::parse(&bytes, 0).expect("supported minor parses");
            assert_eq!(parsed.minor, minor);
        }
    }

    #[test]
    fn rejects_newer_minor() {
        let mut h = sample();
        h.minor = SUPPORTED_MINOR + 1;
        let bytes = h.write();
        let err = SectionHeader::parse(&bytes, 0).unwrap_err();
        assert!(matches!(
            err,
            Error::UnsupportedVersion {
                major: 2,
                minor
            } if minor == SUPPORTED_MINOR + 1
        ));
    }

    #[test]
    fn accepts_unknown_section_type() {
        let mut bytes = sample().write();
        bytes[0x34..0x36].copy_from_slice(&123u16.to_le_bytes());
        let header = SectionHeader::parse(&bytes, 0).expect("unknown types are tolerated");
        assert_eq!(header.section_type, SectionType::Unknown(123));
    }

    #[test]
    fn accepts_unknown_compression_algorithm() {
        let mut bytes = sample().write();
        bytes[0x36..0x38].copy_from_slice(&99u16.to_le_bytes());
        let header = SectionHeader::parse(&bytes, 0).expect("unknown codecs are tolerated");
        assert_eq!(header.compression, Compression::Unknown(99));
    }
}
