//! Crate-wide error type.
//!
//! Every fallible operation in `rdwarfs` returns [`Result<T>`] with
//! this enum. Variants are added as new modules land; each variant
//! carries enough context (offset, section, expected vs actual) to
//! diagnose the failure without needing to re-parse.

use std::io;
use thiserror::Error;

/// Convenience alias for `Result<T, rdwarfs::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// All errors produced by `rdwarfs`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Underlying I/O failure (file open, read, write, seek).
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// The input is shorter than a complete section header (64 bytes)
    /// at the given offset.
    #[error("truncated section header at offset {offset:#x}")]
    TruncatedHeader {
        /// Byte offset at which the header was expected.
        offset: u64,
    },

    /// The section header magic at the given offset is not `DWARFS`.
    #[error("bad section magic at offset {offset:#x}")]
    BadMagic {
        /// Byte offset at which the magic was checked.
        offset: u64,
    },

    /// The input does not contain a DwarFS section header anywhere
    /// in the scanned range.
    #[error("not a dwarfs image")]
    NotADwarfsImage,

    /// The format major version is newer than this build supports.
    #[error("unsupported dwarfs version {major}.{minor}")]
    UnsupportedVersion {
        /// Major version recorded in the section header.
        major: u8,
        /// Minor version recorded in the section header.
        minor: u8,
    },

    /// A section claims a payload length that runs past the end of the
    /// image.
    #[error("truncated section #{number} at offset {offset:#x}")]
    TruncatedSection {
        /// Section number from the header.
        number: u32,
        /// Byte offset of the truncated section header.
        offset: u64,
    },

    /// The section index is malformed (wrong tail entry, unsorted
    /// offsets, or self-listing mismatch).
    #[error("corrupt section index: {reason}")]
    CorruptSectionIndex {
        /// Short human-readable reason describing the violation.
        reason: &'static str,
    },

    /// A section's recorded hash does not match the bytes on disk.
    #[error("integrity mismatch in section #{number} ({kind})")]
    IntegrityMismatch {
        /// Section number from the header.
        number: u32,
        /// Which hash failed (`"xxh3"` or `"sha512_256"`).
        kind: &'static str,
    },

    /// A field declared a count or length that exceeds the configured
    /// cap. Used to defend the read path against hostile inputs.
    #[error("value {value} exceeds cap {cap} for {field}")]
    CapExceeded {
        /// Field or context where the cap was applied.
        field: &'static str,
        /// Cap that was exceeded.
        cap: u64,
        /// Offending value seen in the input.
        value: u64,
    },

    /// The requested codec was not compiled into this build.
    #[error("compression codec {codec} is not enabled")]
    CodecDisabled {
        /// Human-readable codec name.
        codec: &'static str,
    },

    /// The codec is recognized but is not yet implemented in this
    /// build.
    #[error("compression codec {codec} is not implemented")]
    CodecUnimplemented {
        /// Human-readable codec name.
        codec: &'static str,
    },

    /// A read asked for bytes the source cannot supply.
    #[error("read of {len} bytes at offset {offset} exceeds source of {source_len} bytes")]
    SourceOutOfBounds {
        /// Offset the read started at.
        offset: u64,
        /// Number of bytes requested.
        len: u64,
        /// Total length of the source.
        source_len: u64,
    },

    /// The image declares a feature this build does not implement.
    ///
    /// The format spec requires a reader to refuse such an image rather
    /// than risk misinterpreting it.
    #[error("unsupported filesystem feature {name}")]
    UnsupportedFeature {
        /// Feature name recorded in the metadata.
        name: String,
    },

    /// A section uses a compression algorithm this build does not
    /// recognise. The image still opens; only this section is
    /// undecodable.
    #[error("unknown compression algorithm {value}")]
    UnknownCompression {
        /// Raw algorithm value from the section header.
        value: u16,
    },

    /// A codec failed to decode its payload (framing, corruption,
    /// truncation).
    #[error("decode error in {codec}: {message}")]
    Decode {
        /// Human-readable codec name.
        codec: &'static str,
        /// Short human-readable description of the failure.
        message: String,
    },

    /// A codec failed to encode the input.
    #[error("encode error in {codec}: {message}")]
    Encode {
        /// Human-readable codec name.
        codec: &'static str,
        /// Short human-readable description of the failure.
        message: String,
    },
}
