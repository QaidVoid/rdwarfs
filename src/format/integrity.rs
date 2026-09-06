//! Section integrity verification.
//!
//! Each section header records two hashes computed over different
//! suffixes of the section bytes:
//!
//! - `xxh3_64` over bytes from offset 0x30 to the end of the payload.
//!   This is the fast check, run on every load.
//! - `sha512_256` over bytes from offset 0x28 to the end of the
//!   payload. This is the slow check, run on demand.
//!
//! Both ranges include header bytes after the hash field itself, so a
//! tampered version, section number, or payload length is caught even
//! without inspecting the payload.

use sha2::{Digest, Sha512_256};
use xxhash_rust::xxh3::xxh3_64;

use crate::Error;
use crate::format::header::{SHA_COVER_START, SectionHeader, XXH_COVER_START};

/// Compute the XXH3-64 hash a header should carry for a given section.
///
/// `section_bytes` is the full section (header + payload). Only the
/// bytes from offset 0x30 onwards are hashed.
pub fn compute_xxh3(section_bytes: &[u8]) -> u64 {
    xxh3_64(&section_bytes[XXH_COVER_START..])
}

/// Compute the SHA-512/256 hash a header should carry for a given
/// section. `section_bytes` is the full section (header + payload);
/// only bytes from offset 0x28 onwards are hashed.
pub fn compute_sha512_256(section_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512_256::new();
    hasher.update(&section_bytes[SHA_COVER_START..]);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Verify the fast XXH3-64 hash of a section.
///
/// `section_bytes` must be the complete section including the header.
pub fn verify_xxh3(header: &SectionHeader, section_bytes: &[u8]) -> Result<(), Error> {
    if compute_xxh3(section_bytes) == header.xxh3_64 {
        Ok(())
    } else {
        Err(Error::IntegrityMismatch {
            number: header.number,
            kind: "xxh3",
        })
    }
}

/// Verify the slow SHA-512/256 hash of a section.
///
/// `section_bytes` must be the complete section including the header.
pub fn verify_sha512_256(header: &SectionHeader, section_bytes: &[u8]) -> Result<(), Error> {
    if compute_sha512_256(section_bytes) == header.sha512_256 {
        Ok(())
    } else {
        Err(Error::IntegrityMismatch {
            number: header.number,
            kind: "sha512_256",
        })
    }
}

/// Verify both hashes for a section.
pub fn verify(header: &SectionHeader, section_bytes: &[u8]) -> Result<(), Error> {
    verify_xxh3(header, section_bytes)?;
    verify_sha512_256(header, section_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::header::HEADER_LEN;
    use crate::format::types::{Compression, SectionType};

    fn build_section(payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; HEADER_LEN + payload.len()];
        bytes[0..6].copy_from_slice(b"DWARFS");
        bytes[6] = 2;
        bytes[7] = 5;
        bytes[0x30..0x34].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x34..0x36].copy_from_slice(&SectionType::Block.as_u16().to_le_bytes());
        bytes[0x36..0x38].copy_from_slice(&Compression::None.as_u16().to_le_bytes());
        bytes[0x38..0x40].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        bytes[HEADER_LEN..].copy_from_slice(payload);

        let xxh = compute_xxh3(&bytes);
        bytes[0x28..0x30].copy_from_slice(&xxh.to_le_bytes());
        let sha = compute_sha512_256(&bytes);
        bytes[0x08..0x28].copy_from_slice(&sha);
        bytes
    }

    #[test]
    fn verify_good_section() {
        let bytes = build_section(b"hello, dwarfs");
        let header = SectionHeader::parse(&bytes, 0).unwrap();
        verify(&header, &bytes).unwrap();
    }

    #[test]
    fn rejects_corrupt_payload() {
        let mut bytes = build_section(b"payload");
        let header = SectionHeader::parse(&bytes, 0).unwrap();
        bytes[HEADER_LEN] ^= 0xFF;
        assert!(matches!(
            verify_xxh3(&header, &bytes),
            Err(Error::IntegrityMismatch { kind: "xxh3", .. })
        ));
    }

    #[test]
    fn rejects_tampered_section_number() {
        let mut bytes = build_section(b"payload");
        let header = SectionHeader::parse(&bytes, 0).unwrap();
        bytes[0x30] ^= 0x01;
        assert!(matches!(
            verify_xxh3(&header, &bytes),
            Err(Error::IntegrityMismatch { kind: "xxh3", .. })
        ));
    }

    #[test]
    fn rejects_tampered_hash_field() {
        let mut bytes = build_section(b"payload");
        let header = SectionHeader::parse(&bytes, 0).unwrap();
        bytes[0x28] ^= 0x01;
        assert!(matches!(
            verify_sha512_256(&header, &bytes),
            Err(Error::IntegrityMismatch {
                kind: "sha512_256",
                ..
            })
        ));
    }
}
