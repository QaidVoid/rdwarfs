//! Length-driven section iterator.
//!
//! Given a byte slice positioned at a known first-section offset, walk
//! forward by `HEADER_LEN + payload_len` until the input is exhausted.
//! No allocation; each yielded item borrows from the input slice.

use crate::Error;
use crate::format::header::{HEADER_LEN, SectionHeader};

/// A single section located in an in-memory image, borrowing from
/// that buffer.
#[derive(Debug, Clone, Copy)]
pub struct SectionRef<'a> {
    /// Byte offset of the section header within the original file
    /// (including any executable or script prefix).
    pub file_offset: u64,
    /// Parsed section header.
    pub header: SectionHeader,
    /// The full section bytes, header and payload.
    pub bytes: &'a [u8],
}

impl<'a> SectionRef<'a> {
    /// Payload bytes only.
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[HEADER_LEN..]
    }
}

/// Iterator over sections in an image slice.
///
/// `image` is the entire file contents. The iterator begins at the
/// byte offset of the first section header (0 if no executable or
/// script prefix is present).
pub struct Sections<'a> {
    image: &'a [u8],
    cursor: usize,
    done: bool,
}

impl<'a> Sections<'a> {
    /// Construct a new iterator. The caller must already know the
    /// base offset; use [`super::detect_base_offset`] when scanning
    /// for a header behind a prefix.
    pub fn new(image: &'a [u8], base_offset: u64) -> Self {
        Self {
            image,
            cursor: base_offset as usize,
            done: false,
        }
    }
}

impl<'a> Iterator for Sections<'a> {
    type Item = Result<SectionRef<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.cursor >= self.image.len() {
            return None;
        }

        let here = self.cursor;
        if here + HEADER_LEN > self.image.len() {
            self.done = true;
            return Some(Err(Error::TruncatedHeader {
                offset: here as u64,
            }));
        }

        let header_bytes = &self.image[here..here + HEADER_LEN];
        let header = match SectionHeader::parse(header_bytes, here as u64) {
            Ok(h) => h,
            Err(e) => {
                self.done = true;
                return Some(Err(e));
            }
        };

        let section_len = header.section_len() as usize;
        let end = match here.checked_add(section_len) {
            Some(v) if v <= self.image.len() => v,
            _ => {
                self.done = true;
                return Some(Err(Error::TruncatedSection {
                    number: header.number,
                    offset: here as u64,
                }));
            }
        };

        let bytes = &self.image[here..end];
        let item = SectionRef {
            file_offset: here as u64,
            header,
            bytes,
        };
        self.cursor = end;
        Some(Ok(item))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::header::HEADER_LEN;
    use crate::format::integrity::{compute_sha512_256, compute_xxh3};
    use crate::format::types::{Compression, SectionType};

    fn build_section(number: u32, st: SectionType, payload: &[u8]) -> Vec<u8> {
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

    fn build_image(prefix: &[u8], sections: &[(u32, SectionType, &[u8])]) -> Vec<u8> {
        let mut img = prefix.to_vec();
        for (n, t, p) in sections {
            img.extend(build_section(*n, *t, p));
        }
        img
    }

    #[test]
    fn walks_two_sections_no_prefix() {
        let img = build_image(
            &[],
            &[
                (0, SectionType::Block, b"AAAA"),
                (1, SectionType::MetadataV2, b"BBBBBBBB"),
            ],
        );
        let walked: Vec<_> = Sections::new(&img, 0).map(|r| r.unwrap()).collect();
        assert_eq!(walked.len(), 2);
        assert_eq!(walked[0].header.number, 0);
        assert_eq!(walked[0].header.section_type, SectionType::Block);
        assert_eq!(walked[0].payload(), b"AAAA");
        assert_eq!(walked[1].header.number, 1);
        assert_eq!(walked[1].header.section_type, SectionType::MetadataV2);
        assert_eq!(walked[1].payload(), b"BBBBBBBB");
    }

    #[test]
    fn truncated_tail_produces_error() {
        let mut img = build_image(&[], &[(0, SectionType::Block, b"DATA")]);
        img.truncate(img.len() - 1);
        let results: Vec<_> = Sections::new(&img, 0).collect();
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], Err(Error::TruncatedSection { .. })));
    }

    #[test]
    fn walks_with_prefix() {
        let prefix = b"#!/bin/sh\necho hello\n";
        let img = build_image(prefix, &[(0, SectionType::Block, b"X")]);
        let walked: Vec<_> = Sections::new(&img, prefix.len() as u64)
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(walked.len(), 1);
        assert_eq!(walked[0].file_offset, prefix.len() as u64);
    }

    #[test]
    fn iterator_stops_after_error() {
        let mut img = build_image(&[], &[(0, SectionType::Block, b"ABCD")]);
        img.extend([0u8; 8]); // garbage tail too small for a header
        let results: Vec<_> = Sections::new(&img, 0).collect();
        assert!(matches!(results.last(), Some(Err(_))));
    }
}
