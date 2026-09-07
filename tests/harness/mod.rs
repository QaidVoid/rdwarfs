//! Helpers shared by integration tests.
//!
//! This crate is read-only, so tests read committed images rather than
//! building them. Regenerate the images with `tests/make-vectors.sh`.

#![cfg(feature = "read")]
#![allow(dead_code)]

use std::path::PathBuf;

/// Path to a committed test image, by fixture name without extension.
pub fn vector_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(format!("{name}.dwarfs"))
}

/// Bytes of a committed test image.
pub fn vector_bytes(name: &str) -> Vec<u8> {
    std::fs::read(vector_path(name))
        .unwrap_or_else(|e| panic!("read fixture {name}: {e}; run tests/make-vectors.sh"))
}

/// Open a committed test image as a filesystem.
pub fn vector_fs(name: &str) -> rdwarfs::fs::Filesystem {
    let image = rdwarfs::format::Image::from_vec(vector_bytes(name))
        .unwrap_or_else(|e| panic!("parse fixture {name}: {e}"));
    rdwarfs::fs::Filesystem::open(image).unwrap_or_else(|e| panic!("open fixture {name}: {e}"))
}

/// Every fixture built by `make-vectors.sh`, for tests that should hold
/// across all of them.
pub const VECTORS: [&str; 11] = [
    "upstream-default",
    "upstream-uncompressed",
    "upstream-zstd",
    "upstream-lzma",
    "upstream-lz4",
    "upstream-brotli",
    "upstream-small-blocks",
    "upstream-no-index",
    "upstream-unpacked",
    "upstream-packed",
    "upstream-history",
];
