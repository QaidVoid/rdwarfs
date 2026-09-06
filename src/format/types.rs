//! Section-type and compression-algorithm enums.
//!
//! Numeric values come from the MIT-licensed DwarFS format spec
//! (`doc/dwarfs-format.md`, sections "Section Types" and
//! "Compression Algorithms").

/// Type of a DwarFS section, as recorded in the section header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionType {
    /// A block of file data. There can be any number of these, and
    /// they are referenced by chunks in the metadata.
    Block,
    /// The schema describing how to bit-unpack [`SectionType::MetadataV2`].
    /// Stored in Thrift compact encoding.
    MetadataV2Schema,
    /// The bulk Frozen2 metadata blob.
    MetadataV2,
    /// The section index. Must be last and uncompressed when present.
    SectionIndex,
    /// File-system history records. Purely informational, may appear
    /// zero or more times.
    History,
    /// A section type this build does not recognise.
    ///
    /// The format spec ("Features") requires readers to ignore section
    /// types they do not know as long as the format minor version is
    /// unchanged, so an image carrying one still opens and every
    /// recognised section stays usable.
    Unknown(u16),
}

impl SectionType {
    /// Interpret a raw header value.
    ///
    /// Values this build does not recognise map to
    /// [`SectionType::Unknown`] rather than failing.
    pub fn from_u16(value: u16) -> Self {
        match value {
            0 => Self::Block,
            7 => Self::MetadataV2Schema,
            8 => Self::MetadataV2,
            9 => Self::SectionIndex,
            10 => Self::History,
            other => Self::Unknown(other),
        }
    }

    /// The numeric value stored in the section header.
    pub fn as_u16(self) -> u16 {
        match self {
            Self::Block => 0,
            Self::MetadataV2Schema => 7,
            Self::MetadataV2 => 8,
            Self::SectionIndex => 9,
            Self::History => 10,
            Self::Unknown(value) => value,
        }
    }
}

/// Compression algorithm used for a section payload.
///
/// `Flac` and `Ricepp` are accepted by the enum so an image can be
/// inspected even when the corresponding codec is not compiled in;
/// the actual decoder is feature-gated and will fail to decode in that
/// case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Compression {
    /// Stored as-is.
    None,
    /// LZMA, framed as an xz container stream.
    Lzma,
    /// Zstandard, one-shot frame carrying content size in the frame
    /// header.
    Zstd,
    /// LZ4 block, prefixed by a 4-byte little-endian uncompressed
    /// length.
    Lz4,
    /// LZ4HC block, framed identically to [`Compression::Lz4`].
    Lz4Hc,
    /// Brotli stream, prefixed by an unsigned LEB128 uncompressed
    /// length.
    Brotli,
    /// FLAC stream for audio-aware categorization.
    Flac,
    /// RICEPP stream for integer-aware categorization.
    Ricepp,
    /// An algorithm this build does not recognise.
    ///
    /// Carrying the raw value keeps an image openable when only some
    /// of its sections use a future codec. Decoding such a section
    /// fails; decoding every other section still works.
    Unknown(u16),
}

impl Compression {
    /// Interpret a raw header value.
    ///
    /// Values this build does not recognise map to
    /// [`Compression::Unknown`] rather than failing.
    pub fn from_u16(value: u16) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Lzma,
            2 => Self::Zstd,
            3 => Self::Lz4,
            4 => Self::Lz4Hc,
            5 => Self::Brotli,
            6 => Self::Flac,
            7 => Self::Ricepp,
            other => Self::Unknown(other),
        }
    }

    /// The numeric value stored in the section header.
    pub fn as_u16(self) -> u16 {
        match self {
            Self::None => 0,
            Self::Lzma => 1,
            Self::Zstd => 2,
            Self::Lz4 => 3,
            Self::Lz4Hc => 4,
            Self::Brotli => 5,
            Self::Flac => 6,
            Self::Ricepp => 7,
            Self::Unknown(value) => value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_type_roundtrip() {
        for value in [0u16, 7, 8, 9, 10] {
            assert_eq!(SectionType::from_u16(value).as_u16(), value);
        }
    }

    #[test]
    fn section_type_preserves_unknown_values() {
        for value in [1u16, 6, 11, 0xFFFF] {
            let kind = SectionType::from_u16(value);
            assert_eq!(kind, SectionType::Unknown(value));
            assert_eq!(kind.as_u16(), value);
        }
    }

    #[test]
    fn compression_roundtrip() {
        for value in 0u16..=7 {
            assert_eq!(Compression::from_u16(value).as_u16(), value);
        }
    }

    #[test]
    fn compression_preserves_unknown_values() {
        for value in [8u16, 42, 0xFFFF] {
            let codec = Compression::from_u16(value);
            assert_eq!(codec, Compression::Unknown(value));
            assert_eq!(codec.as_u16(), value);
        }
    }
}
