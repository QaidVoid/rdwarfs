//! Automatic detection of the first section in an image.
//!
//! A DwarFS file may be prefixed by an arbitrary executable or shell
//! script (the "self-extracting" pattern). The first section is
//! located by scanning forward for the magic bytes `DWARFS`, parsing a
//! candidate header, and confirming the next section (or end of file)
//! also lines up. This matches the procedure described in the MIT
//! format spec ("Header Detection").

use crate::Error;
use crate::format::header::{HEADER_LEN, MAGIC, SectionHeader};
#[cfg(feature = "read")]
use crate::format::source::ImageSource;

/// Bytes read per probe when scanning a source that cannot expose a
/// contiguous slice. Consecutive probes overlap by `MAGIC.len() - 1`
/// so a magic straddling a boundary is still found.
#[cfg(feature = "read")]
const SCAN_CHUNK: usize = 64 * 1024;

/// Locate the first section in `source`.
///
/// Sources backed by contiguous memory are scanned in place; the rest
/// are scanned through overlapping positional reads.
#[cfg(feature = "read")]
pub(crate) fn detect_base_offset_in(source: &dyn ImageSource) -> Result<u64, Error> {
    if let Some(bytes) = source.as_slice() {
        return detect_base_offset(bytes);
    }

    let total = source.len();
    if total < HEADER_LEN as u64 {
        return Err(Error::NotADwarfsImage);
    }
    let last_header_start = total - HEADER_LEN as u64;

    let mut version_error: Option<Error> = None;
    let mut window = vec![0u8; SCAN_CHUNK];
    let mut probe: u64 = 0;

    while probe <= last_header_start {
        let want = SCAN_CHUNK.min((total - probe) as usize);
        let window = &mut window[..want];
        source.read_exact_at(window, probe)?;

        let mut at = 0usize;
        while let Some(rel) = find_magic(&window[at..]) {
            let candidate = probe + (at + rel) as u64;
            if candidate > last_header_start {
                return Err(version_error.unwrap_or(Error::NotADwarfsImage));
            }
            match read_header(source, candidate) {
                Ok(header) => {
                    if source_follows_a_section_boundary(source, candidate, &header)? {
                        return Ok(candidate);
                    }
                }
                Err(err @ Error::UnsupportedVersion { .. }) => {
                    version_error.get_or_insert(err);
                }
                Err(_) => {}
            }
            at += rel + 1;
        }

        if want < SCAN_CHUNK {
            break;
        }
        probe += (SCAN_CHUNK - (MAGIC.len() - 1)) as u64;
    }

    Err(version_error.unwrap_or(Error::NotADwarfsImage))
}

#[cfg(feature = "read")]
fn read_header(source: &dyn ImageSource, at: u64) -> Result<SectionHeader, Error> {
    let mut buf = [0u8; HEADER_LEN];
    source.read_exact_at(&mut buf, at)?;
    SectionHeader::parse(&buf, at)
}

#[cfg(feature = "read")]
fn source_follows_a_section_boundary(
    source: &dyn ImageSource,
    at: u64,
    header: &SectionHeader,
) -> Result<bool, Error> {
    let Some(next) = at.checked_add(header.section_len()) else {
        return Ok(false);
    };
    let total = source.len();
    if next == total {
        return Ok(true);
    }
    if next + MAGIC.len() as u64 > total {
        return Ok(false);
    }
    let mut magic = [0u8; MAGIC.len()];
    source.read_exact_at(&mut magic, next)?;
    Ok(magic == MAGIC)
}

/// Locate the byte offset of the first section in `image`.
///
/// Returns `Ok(offset)` where `offset` is 0 if no prefix is present.
/// Returns [`Error::NotADwarfsImage`] if no valid header can be found
/// in the input.
pub fn detect_base_offset(image: &[u8]) -> Result<u64, Error> {
    if image.len() < HEADER_LEN {
        return Err(Error::NotADwarfsImage);
    }

    let last_header_start = image.len() - HEADER_LEN;
    let mut probe = 0usize;
    // Remembered so an image whose version this build does not support
    // reports that, rather than the far less useful claim that the
    // input is not a DwarFS image at all.
    let mut version_error: Option<Error> = None;

    while probe <= last_header_start {
        let Some(rel) = find_magic(&image[probe..]) else {
            break;
        };
        let candidate = probe + rel;
        if candidate > last_header_start {
            break;
        }

        match SectionHeader::parse(&image[candidate..candidate + HEADER_LEN], candidate as u64) {
            Ok(header) => {
                if follows_a_section_boundary(image, candidate, &header) {
                    return Ok(candidate as u64);
                }
            }
            Err(err @ Error::UnsupportedVersion { .. }) => {
                version_error.get_or_insert(err);
            }
            Err(_) => {}
        }

        probe = candidate + 1;
    }

    Err(version_error.unwrap_or(Error::NotADwarfsImage))
}

fn find_magic(slice: &[u8]) -> Option<usize> {
    slice
        .windows(MAGIC.len())
        .position(|window| window == MAGIC)
}

/// Confirm a candidate by checking that the section it describes is
/// followed either by the end of the image or by another section magic.
fn follows_a_section_boundary(image: &[u8], at: usize, header: &SectionHeader) -> bool {
    let Some(next) = at.checked_add(header.section_len() as usize) else {
        return false;
    };

    if next == image.len() {
        return true;
    }
    let Some(magic_end) = next.checked_add(MAGIC.len()) else {
        return false;
    };
    if magic_end > image.len() {
        return false;
    }
    image[next..magic_end] == MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::header::HEADER_LEN;
    use crate::format::integrity::{compute_sha512_256, compute_xxh3};
    use crate::format::types::{Compression, SectionType};

    fn section(number: u32, st: SectionType, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; HEADER_LEN + payload.len()];
        bytes[0..6].copy_from_slice(b"DWARFS");
        bytes[6] = 2;
        bytes[7] = 5;
        bytes[0x30..0x34].copy_from_slice(&number.to_le_bytes());
        bytes[0x34..0x36].copy_from_slice(&st.as_u16().to_le_bytes());
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
    fn no_prefix() {
        let mut img = section(0, SectionType::Block, b"AAAA");
        img.extend(section(1, SectionType::MetadataV2, b"BBBB"));
        assert_eq!(detect_base_offset(&img).unwrap(), 0);
    }

    #[test]
    fn shell_prefix() {
        let prefix = b"#!/bin/sh\nexec dwarfs \"$@\"\n";
        let mut img = prefix.to_vec();
        img.extend(section(0, SectionType::Block, b"X"));
        img.extend(section(1, SectionType::MetadataV2, b"Y"));
        assert_eq!(detect_base_offset(&img).unwrap(), prefix.len() as u64);
    }

    #[test]
    fn ignores_decoy_magic_in_prefix() {
        let mut img = b"prefix DWARFS not a header here ".to_vec();
        let pad_len = img.len();
        img.extend(section(0, SectionType::Block, b"P"));
        let base = detect_base_offset(&img).unwrap();
        assert_eq!(base, pad_len as u64);
    }

    #[test]
    fn single_section_with_no_trailing_bytes() {
        let img = section(0, SectionType::Block, b"only");
        assert_eq!(detect_base_offset(&img).unwrap(), 0);
    }

    #[test]
    fn rejects_pure_garbage() {
        let img = vec![0u8; 256];
        assert!(matches!(
            detect_base_offset(&img),
            Err(Error::NotADwarfsImage)
        ));
    }
}
