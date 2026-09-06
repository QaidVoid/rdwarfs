//! DwarFS block compression.
//!
//! Each section payload is compressed with one of the codecs in
//! [`Compression`]. This module exposes a single entry point for
//! decoding (and, when `write` is enabled, encoding) any supported
//! codec, validates the framing each codec uses, and bounds the
//! decoded size to defend against hostile inputs.
//!
//! Framing is documented in the spec and each codec's submodule.

#[cfg(feature = "read")]
mod capped;

mod none;

#[cfg(feature = "brotli")]
mod brotli;
#[cfg(feature = "lz4")]
mod lz4;
#[cfg(feature = "lzma")]
mod lzma;
#[cfg(feature = "zstd")]
mod zstd;

#[cfg(feature = "read")]
use crate::Error;
use crate::format::Compression;

#[cfg(feature = "read")]
pub use capped::CappedWriter;

/// Human-readable name for a [`Compression`] variant, used in error
/// messages.
pub fn codec_name(codec: Compression) -> &'static str {
    match codec {
        Compression::None => "none",
        Compression::Lzma => "lzma",
        Compression::Zstd => "zstd",
        Compression::Lz4 => "lz4",
        Compression::Lz4Hc => "lz4hc",
        Compression::Brotli => "brotli",
        Compression::Flac => "flac",
        Compression::Ricepp => "ricepp",
        Compression::Unknown(_) => "unknown",
    }
}

/// Decode a compressed section payload.
///
/// `cap` is the maximum number of decoded bytes the call may produce;
/// any codec output beyond `cap` returns an [`Error::Decode`]. The cap
/// is the only memory bound on the decode path.
#[cfg(feature = "read")]
pub fn decompress(codec: Compression, src: &[u8], cap: usize) -> Result<Vec<u8>, Error> {
    match codec {
        Compression::None => none::decompress(src, cap),

        #[cfg(feature = "zstd")]
        Compression::Zstd => zstd::decompress(src, cap),
        #[cfg(not(feature = "zstd"))]
        Compression::Zstd => Err(Error::CodecDisabled { codec: "zstd" }),
        #[cfg(feature = "lzma")]
        Compression::Lzma => lzma::decompress(src, cap),
        #[cfg(not(feature = "lzma"))]
        Compression::Lzma => Err(Error::CodecDisabled { codec: "lzma" }),
        #[cfg(feature = "lz4")]
        Compression::Lz4 | Compression::Lz4Hc => lz4::decompress(src, cap),
        #[cfg(not(feature = "lz4"))]
        Compression::Lz4 | Compression::Lz4Hc => Err(Error::CodecDisabled { codec: "lz4" }),
        #[cfg(feature = "brotli")]
        Compression::Brotli => brotli::decompress(src, cap),
        #[cfg(not(feature = "brotli"))]
        Compression::Brotli => Err(Error::CodecDisabled { codec: "brotli" }),
        Compression::Flac => Err(Error::CodecUnimplemented { codec: "flac" }),
        Compression::Ricepp => Err(Error::CodecUnimplemented { codec: "ricepp" }),
        Compression::Unknown(value) => Err(Error::UnknownCompression { value }),
    }
}
