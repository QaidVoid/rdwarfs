//! Optional `SECTION_INDEX` parser.
//!
//! When present, the section index is the last section in the image
//! and is stored uncompressed. Its payload is an array of 64-bit
//! little-endian entries: the top 16 bits hold a section type, the
//! bottom 48 bits the offset of that section from the base of the
//! first section. The index lists itself as its final entry.
//!
//! Spec: `doc/dwarfs-format.md`, "Section Types" / `SECTION_INDEX`.

use crate::Error;
use crate::format::header::{HEADER_LEN, SectionHeader};
use crate::format::source::{ImageSource, read_range};
use crate::format::types::{Compression, SectionType};

/// One row of the section index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexEntry {
    /// Section type recorded in the index row.
    pub section_type: SectionType,
    /// Offset of that section's header from the base (first-section
    /// offset, i.e. excluding any executable or script prefix).
    pub offset_from_base: u64,
}

/// The parsed section index.
#[derive(Debug, Clone)]
pub struct SectionIndex {
    /// Entries in the order they appear in the index (sorted by
    /// offset; the last entry references the index itself).
    pub entries: Vec<IndexEntry>,
    /// File offset of the index section's own header.
    pub file_offset: u64,
}

const OFFSET_MASK: u64 = (1u64 << 48) - 1;

impl SectionIndex {
    /// Attempt to locate and parse the section index in `image`.
    ///
    /// Returns `Ok(None)` if no index is present (the last 64-bit
    /// value does not encode a `SECTION_INDEX` type marker). Returns
    /// `Err` only when an index *is* present but malformed.
    pub fn from_source(source: &dyn ImageSource, base_offset: u64) -> Result<Option<Self>, Error> {
        let total = source.len();
        if total < 8 {
            return Ok(None);
        }
        let mut tail = [0u8; 8];
        source.read_exact_at(&mut tail, total - 8)?;
        let entry = u64::from_le_bytes(tail);
        if ((entry >> 48) & 0xFFFF) as u16 != SectionType::SectionIndex.as_u16() {
            return Ok(None);
        }
        let header_file_offset =
            base_offset
                .checked_add(entry & OFFSET_MASK)
                .ok_or(Error::CorruptSectionIndex {
                    reason: "tail offset overflows file size",
                })?;
        if header_file_offset.saturating_add(HEADER_LEN as u64) > total {
            return Err(Error::CorruptSectionIndex {
                reason: "tail offset past end of image",
            });
        }
        let mut header_bytes = [0u8; HEADER_LEN];
        source.read_exact_at(&mut header_bytes, header_file_offset)?;
        let header = SectionHeader::parse(&header_bytes, header_file_offset)?;
        if header.section_type != SectionType::SectionIndex {
            return Err(Error::CorruptSectionIndex {
                reason: "tail offset does not point to SECTION_INDEX",
            });
        }
        if header.compression != Compression::None {
            return Err(Error::CorruptSectionIndex {
                reason: "section index must be uncompressed",
            });
        }
        let payload_start = header_file_offset + HEADER_LEN as u64;
        let payload_end =
            payload_start
                .checked_add(header.payload_len)
                .ok_or(Error::CorruptSectionIndex {
                    reason: "payload length overflows",
                })?;
        if payload_end != total {
            return Err(Error::CorruptSectionIndex {
                reason: "section index must be the last section",
            });
        }
        let payload = read_range(source, payload_start, header.payload_len)?;
        Self::parse_entries(&payload, header_file_offset).map(Some)
    }

    /// Decode the index payload into entries and validate their order.
    fn parse_entries(payload: &[u8], file_offset: u64) -> Result<Self, Error> {
        if payload.len() % 8 != 0 {
            return Err(Error::CorruptSectionIndex {
                reason: "payload length is not a multiple of 8",
            });
        }
        let count = payload.len() / 8;
        if count == 0 {
            return Err(Error::CorruptSectionIndex {
                reason: "index has zero entries",
            });
        }
        let mut entries = Vec::with_capacity(count);
        let mut prev_offset: Option<u64> = None;
        for chunk in payload.chunks_exact(8) {
            let raw = u64::from_le_bytes(chunk.try_into().unwrap());
            let off = raw & OFFSET_MASK;
            if let Some(p) = prev_offset
                && off <= p
            {
                return Err(Error::CorruptSectionIndex {
                    reason: "entries not strictly sorted by offset",
                });
            }
            prev_offset = Some(off);
            entries.push(IndexEntry {
                section_type: SectionType::from_u16(((raw >> 48) & 0xFFFF) as u16),
                offset_from_base: off,
            });
        }
        let last = entries.last().expect("count >= 1");
        if last.section_type != SectionType::SectionIndex {
            return Err(Error::CorruptSectionIndex {
                reason: "last entry is not the index itself",
            });
        }
        Ok(Self {
            entries,
            file_offset,
        })
    }

    /// Find the offset (from base) of the first section of the given
    /// type, if any.
    pub fn find(&self, kind: SectionType) -> Option<u64> {
        self.entries
            .iter()
            .find(|e| e.section_type == kind)
            .map(|e| e.offset_from_base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::integrity::{compute_sha512_256, compute_xxh3};

    fn finish_section(bytes: &mut [u8]) {
        let xxh = compute_xxh3(bytes);
        bytes[0x28..0x30].copy_from_slice(&xxh.to_le_bytes());
        let sha = compute_sha512_256(bytes);
        bytes[0x08..0x28].copy_from_slice(&sha);
    }

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
        finish_section(&mut bytes);
        bytes
    }

    fn build_image_with_index(prefix: &[u8], body: &[(u32, SectionType, &[u8])]) -> (Vec<u8>, u64) {
        let mut image = prefix.to_vec();
        let base_offset = image.len() as u64;
        let mut entries: Vec<(SectionType, u64)> = Vec::new();

        for (number, kind, payload) in body {
            let here = image.len() as u64;
            entries.push((*kind, here - base_offset));
            image.extend(section(*number, *kind, payload));
        }

        let index_offset_rel = image.len() as u64 - base_offset;
        entries.push((SectionType::SectionIndex, index_offset_rel));

        let mut payload = Vec::with_capacity(entries.len() * 8);
        for (kind, off) in &entries {
            let raw = (u64::from(kind.as_u16()) << 48) | *off;
            payload.extend_from_slice(&raw.to_le_bytes());
        }

        let next_number = body.last().map(|b| b.0 + 1).unwrap_or(0);
        image.extend(section(next_number, SectionType::SectionIndex, &payload));
        (image, base_offset)
    }

    #[test]
    fn detects_no_index() {
        let img = section(0, SectionType::Block, b"X");
        assert!(SectionIndex::from_source(&img, 0).unwrap().is_none());
    }

    #[test]
    fn parses_valid_index() {
        let (img, base) = build_image_with_index(
            &[],
            &[
                (0, SectionType::Block, b"AAAA"),
                (1, SectionType::MetadataV2Schema, b"S"),
                (2, SectionType::MetadataV2, b"MMMMM"),
            ],
        );
        let index = SectionIndex::from_source(&img, base).unwrap().unwrap();
        assert_eq!(index.entries.len(), 4);
        assert_eq!(index.entries[0].section_type, SectionType::Block);
        assert_eq!(index.entries[0].offset_from_base, 0);
        assert_eq!(
            index.entries.last().unwrap().section_type,
            SectionType::SectionIndex
        );
        assert_eq!(index.find(SectionType::MetadataV2), Some(64 + 4 + 64 + 1));
        assert_eq!(index.find(SectionType::History), None);
    }

    #[test]
    fn rejects_index_compressed_marker() {
        let (mut img, base) = build_image_with_index(&[], &[(0, SectionType::Block, b"X")]);

        let index_hdr_pos = img.len() - (64 + 16);
        img[index_hdr_pos + 0x36..index_hdr_pos + 0x38]
            .copy_from_slice(&Compression::Zstd.as_u16().to_le_bytes());
        finish_section(&mut img[index_hdr_pos..]);

        let err = SectionIndex::from_source(&img, base).unwrap_err();
        assert!(matches!(err, Error::CorruptSectionIndex { .. }));
    }

    #[test]
    fn rejects_unsorted_entries() {
        let mut prefix = Vec::new();
        let mut image = prefix.clone();
        let mut entries: Vec<(SectionType, u64)> = Vec::new();

        let payload = b"AAAA";
        let here = image.len() as u64;
        entries.push((SectionType::Block, here));
        image.extend(section(0, SectionType::Block, payload));

        let here = image.len() as u64;
        entries.push((SectionType::MetadataV2, here));
        image.extend(section(1, SectionType::MetadataV2, b"M"));

        entries.swap(0, 1);

        let index_offset = image.len() as u64;
        entries.push((SectionType::SectionIndex, index_offset));

        let mut payload = Vec::with_capacity(entries.len() * 8);
        for (kind, off) in &entries {
            let raw = (u64::from(kind.as_u16()) << 48) | *off;
            payload.extend_from_slice(&raw.to_le_bytes());
        }
        image.extend(section(2, SectionType::SectionIndex, &payload));
        prefix.extend(image);

        let err = SectionIndex::from_source(&prefix, 0).unwrap_err();
        assert!(matches!(err, Error::CorruptSectionIndex { .. }));
    }
}
