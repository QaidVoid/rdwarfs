//! `Image`: the top-level read-side handle for a DwarFS file.
//!
//! An `Image` owns an [`ImageSource`], records the first-section byte
//! offset, and provides cheap access to the full section list and the
//! section index when present. Integrity verification is exposed as
//! fast (XXH3-64) and deep (SHA-512/256) passes.

use std::borrow::Cow;

use crate::Error;
use crate::compression;
use crate::format::detect::detect_base_offset_in;
use crate::format::header::{HEADER_LEN, SectionHeader};
use crate::format::index::SectionIndex;
use crate::format::integrity::{verify_sha512_256, verify_xxh3};
use crate::format::source::{ImageSource, read_range};
use crate::format::types::SectionType;

/// A located section: byte offset within the file plus a parsed
/// header.
#[derive(Debug, Clone, Copy)]
pub struct SectionRecord {
    /// Byte offset of the section header in the original file.
    pub file_offset: u64,
    /// Parsed header.
    pub header: SectionHeader,
}

impl SectionRecord {
    /// Total byte length of this section on disk (header plus
    /// payload).
    pub fn section_len(&self) -> u64 {
        self.header.section_len()
    }
}

/// A DwarFS image opened for reading.
///
/// Construction parses every section header and the section index
/// (when present) but does not decompress any payload. All accessors
/// are O(1) or O(n) over the section list.
pub struct Image {
    source: Box<dyn ImageSource>,
    base_offset: u64,
    sections: Vec<SectionRecord>,
    section_index: Option<SectionIndex>,
}

impl std::fmt::Debug for Image {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Image")
            .field("len", &self.len())
            .field("base_offset", &self.base_offset)
            .field("sections", &self.sections.len())
            .field("section_index", &self.section_index.is_some())
            .finish()
    }
}

impl Image {
    /// Open an image over any [`ImageSource`].
    pub fn from_source<S: ImageSource + 'static>(source: S) -> Result<Self, Error> {
        Self::build(Box::new(source))
    }

    /// Open an image occupying `len` bytes at `offset` of `source`.
    ///
    /// Bytes outside the window are never read, so this is how an image
    /// embedded in a larger file is opened. Section offsets reported by
    /// the resulting image are relative to the window, not to the
    /// underlying file.
    pub fn from_window<S: ImageSource + 'static>(
        source: S,
        offset: u64,
        len: u64,
    ) -> Result<Self, Error> {
        Self::from_source(crate::format::WindowedSource::new(source, offset, len)?)
    }

    /// Open an image whose bytes are already in memory.
    pub fn from_vec(bytes: Vec<u8>) -> Result<Self, Error> {
        Self::from_source(bytes)
    }

    /// Open an image stored at `path`.
    ///
    /// With the `mmap` feature the file is memory-mapped, which is
    /// fast but means an I/O error faults the process rather than
    /// returning an error. Without it the file is read positionally.
    /// Construct the source directly to choose explicitly.
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> Result<Self, Error> {
        #[cfg(feature = "mmap")]
        {
            let file = std::fs::File::open(path.as_ref())?;
            // SAFETY: the map is read-only. The caller must not modify
            // the file while the image is live, which is the standard
            // mmap contract and is documented above.
            let mmap = unsafe { memmap2::Mmap::map(&file)? };
            Self::from_source(mmap)
        }
        #[cfg(not(feature = "mmap"))]
        {
            Self::from_source(crate::format::FileSource::open(path)?)
        }
    }

    fn build(source: Box<dyn ImageSource>) -> Result<Self, Error> {
        let base_offset = detect_base_offset_in(source.as_ref())?;
        let sections = walk_sections(source.as_ref(), base_offset)?;
        let section_index = SectionIndex::from_source(source.as_ref(), base_offset)?;
        Ok(Self {
            source,
            base_offset,
            sections,
            section_index,
        })
    }

    /// Borrow the underlying source.
    pub fn source(&self) -> &dyn ImageSource {
        self.source.as_ref()
    }

    /// Total number of bytes the image occupies.
    pub fn len(&self) -> u64 {
        self.source.len()
    }

    /// Whether the image is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// File offset of the first section header (zero if there is no
    /// executable or script prefix).
    pub fn base_offset(&self) -> u64 {
        self.base_offset
    }

    /// All section records in file order.
    pub fn sections(&self) -> &[SectionRecord] {
        &self.sections
    }

    /// The parsed section index, if the image contains one.
    pub fn section_index(&self) -> Option<&SectionIndex> {
        self.section_index.as_ref()
    }

    /// Find the first section of the given type, if any.
    pub fn find_section(&self, kind: SectionType) -> Option<&SectionRecord> {
        self.sections.iter().find(|s| s.header.section_type == kind)
    }

    /// Read `len` bytes at `offset`.
    ///
    /// Borrows from the source when it is backed by contiguous memory
    /// and copies otherwise, so a caller never has to branch on which
    /// kind of source it was handed.
    pub fn read_range(&self, offset: u64, len: u64) -> Result<Cow<'_, [u8]>, Error> {
        read_range(self.source.as_ref(), offset, len)
    }

    /// Full bytes of a section (header plus payload).
    pub fn section_bytes(&self, record: &SectionRecord) -> Result<Cow<'_, [u8]>, Error> {
        self.read_range(record.file_offset, record.section_len())
    }

    /// Payload bytes of a section (compressed if the codec is not
    /// `NONE`).
    pub fn payload_bytes(&self, record: &SectionRecord) -> Result<Cow<'_, [u8]>, Error> {
        self.read_range(
            record.file_offset + HEADER_LEN as u64,
            record.header.payload_len,
        )
    }

    /// Verify the fast XXH3-64 hash on every section.
    pub fn verify_all(&self) -> Result<(), Error> {
        self.verify_sections(false)
    }

    /// Verify both the XXH3-64 and SHA-512/256 hash on every section.
    pub fn verify_deep(&self) -> Result<(), Error> {
        self.verify_sections(true)
    }

    /// Decode at least `needed` bytes from the front of a section.
    ///
    /// Returns `None` when the codec cannot stop early. Verifies the
    /// section hash first, exactly as a full decode does, so a partial
    /// decode is no less checked than a whole one.
    pub fn decompress_section_prefix(
        &self,
        record: &SectionRecord,
        needed: usize,
    ) -> Result<Option<Vec<u8>>, Error> {
        let section = self.section_bytes(record)?;
        verify_xxh3(&record.header, &section)?;
        compression::decompress_prefix(record.header.compression, &section[HEADER_LEN..], needed)
    }

    /// Hash every section, optionally including the slower SHA.
    ///
    /// Sections are independent, so on a build with the `parallel`
    /// feature they are hashed across a thread pool. SHA-512/256 over
    /// a whole image dominates the cost of a deep check.
    fn verify_sections(&self, deep: bool) -> Result<(), Error> {
        let one = |record: &SectionRecord| -> Result<(), Error> {
            let bytes = self.section_bytes(record)?;
            verify_xxh3(&record.header, &bytes)?;
            if deep {
                verify_sha512_256(&record.header, &bytes)?;
            }
            Ok(())
        };
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            self.sections.par_iter().try_for_each(one)
        }
        #[cfg(not(feature = "parallel"))]
        {
            self.sections.iter().try_for_each(one)
        }
    }

    /// Decompress a section payload through the registered codec
    /// dispatch. `cap` is the maximum decoded size allowed; codecs
    /// signal [`Error::Decode`] when output would exceed it.
    ///
    /// The section's fast hash is checked before the payload is
    /// decoded, so corrupt bytes are never handed to a codec or
    /// returned to a caller. The format spec notes that this hash is
    /// cheap enough to check every time a section is loaded, which is
    /// what makes verifying here rather than in an eager whole-image
    /// pass affordable.
    pub fn decompress_section(&self, record: &SectionRecord, cap: usize) -> Result<Vec<u8>, Error> {
        let section = self.section_bytes(record)?;
        verify_xxh3(&record.header, &section)?;
        compression::decompress(record.header.compression, &section[HEADER_LEN..], cap)
    }
}

/// Parse every section header from `base_offset` to the end of the
/// source, walking forward by each section's recorded length.
fn walk_sections(source: &dyn ImageSource, base_offset: u64) -> Result<Vec<SectionRecord>, Error> {
    let end = source.len();
    let mut sections = Vec::new();
    let mut cursor = base_offset;
    let mut header = [0u8; HEADER_LEN];

    while cursor < end {
        if cursor + HEADER_LEN as u64 > end {
            return Err(Error::TruncatedHeader { offset: cursor });
        }
        source.read_exact_at(&mut header, cursor)?;
        let parsed = SectionHeader::parse(&header, cursor)?;
        let section_len = parsed.section_len();
        let next = cursor
            .checked_add(section_len)
            .filter(|next| *next <= end)
            .ok_or(Error::TruncatedSection {
                number: parsed.number,
                offset: cursor,
            })?;
        sections.push(SectionRecord {
            file_offset: cursor,
            header: parsed,
        });
        cursor = next;
    }
    Ok(sections)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::integrity::{compute_sha512_256, compute_xxh3};
    use crate::format::types::Compression;

    fn finish_section(bytes: &mut [u8]) {
        let xxh = compute_xxh3(bytes);
        bytes[0x28..0x30].copy_from_slice(&xxh.to_le_bytes());
        let sha = compute_sha512_256(bytes);
        bytes[0x08..0x28].copy_from_slice(&sha);
    }

    fn section(number: u32, kind: SectionType, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; HEADER_LEN + payload.len()];
        bytes[0..6].copy_from_slice(b"DWARFS");
        bytes[6] = 2;
        bytes[7] = 5;
        bytes[0x30..0x34].copy_from_slice(&number.to_le_bytes());
        bytes[0x34..0x36].copy_from_slice(&kind.as_u16().to_le_bytes());
        bytes[0x36..0x38].copy_from_slice(&Compression::None.as_u16().to_le_bytes());
        bytes[0x38..0x40].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        bytes[HEADER_LEN..].copy_from_slice(payload);
        finish_section(&mut bytes);
        bytes
    }

    fn build_image(prefix: &[u8], body: &[(u32, SectionType, &[u8])], with_index: bool) -> Vec<u8> {
        let mut image = prefix.to_vec();
        let base = image.len() as u64;
        let mut entries: Vec<(SectionType, u64)> = Vec::new();
        for (n, k, p) in body {
            let here = image.len() as u64;
            entries.push((*k, here - base));
            image.extend(section(*n, *k, p));
        }

        if with_index {
            let here = image.len() as u64;
            entries.push((SectionType::SectionIndex, here - base));
            let mut payload = Vec::with_capacity(entries.len() * 8);
            for (k, off) in &entries {
                let raw = (u64::from(k.as_u16()) << 48) | *off;
                payload.extend_from_slice(&raw.to_le_bytes());
            }
            let next = body.last().map(|b| b.0 + 1).unwrap_or(0);
            image.extend(section(next, SectionType::SectionIndex, &payload));
        }
        image
    }

    #[test]
    fn opens_image_without_index() {
        let img = build_image(
            &[],
            &[
                (0, SectionType::Block, b"AAAA"),
                (1, SectionType::MetadataV2, b"MMMM"),
            ],
            false,
        );
        let image = Image::from_vec(img).unwrap();
        assert_eq!(image.base_offset(), 0);
        assert_eq!(image.sections().len(), 2);
        assert!(image.section_index().is_none());
        assert_eq!(
            image
                .find_section(SectionType::MetadataV2)
                .map(|s| s.file_offset),
            Some((HEADER_LEN + 4) as u64)
        );
    }

    #[test]
    fn opens_image_with_index_and_prefix() {
        let prefix = b"#!/bin/sh\n";
        let img = build_image(
            prefix,
            &[
                (0, SectionType::Block, b"AAAA"),
                (1, SectionType::MetadataV2, b"MMMM"),
            ],
            true,
        );
        let image = Image::from_vec(img).unwrap();
        assert_eq!(image.base_offset(), prefix.len() as u64);
        assert_eq!(image.sections().len(), 3);
        assert_eq!(
            image.section_index().map(|i| i.entries.len()).unwrap_or(0),
            3
        );
    }

    #[test]
    fn verify_all_accepts_clean_image() {
        let img = build_image(&[], &[(0, SectionType::Block, b"hello")], true);
        Image::from_vec(img).unwrap().verify_all().unwrap();
    }

    #[test]
    fn verify_deep_accepts_clean_image() {
        let img = build_image(&[], &[(0, SectionType::Block, b"hello")], true);
        Image::from_vec(img).unwrap().verify_deep().unwrap();
    }

    #[test]
    fn verify_all_rejects_payload_corruption() {
        let mut img = build_image(&[], &[(0, SectionType::Block, b"PAYLOAD")], false);
        let payload_off = HEADER_LEN;
        img[payload_off] ^= 0x80;
        let image = Image::from_vec(img).unwrap();
        assert!(matches!(
            image.verify_all(),
            Err(Error::IntegrityMismatch { kind: "xxh3", .. })
        ));
    }

    #[test]
    fn payload_bytes_match_header_length() {
        let img = build_image(&[], &[(0, SectionType::Block, b"XYZ")], false);
        let image = Image::from_vec(img).unwrap();
        let s = &image.sections()[0];
        assert_eq!(&*image.payload_bytes(s).unwrap(), b"XYZ");
        assert_eq!(image.section_bytes(s).unwrap().len(), HEADER_LEN + 3);
    }
}
