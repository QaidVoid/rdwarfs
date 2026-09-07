//! Independent Rust library and tools for reading DwarFS
//! (Deduplicating Warp-speed Advanced Read-only File System) images.
//!
//! `rdwarfs` is a from-scratch, dual-licensed (MIT OR Apache-2.0)
//! reader for the `.dwarfs` format. It exposes a synchronous,
//! library-first API for random access into an image, and ships thin
//! CLI tools for inspecting, extracting and mounting one.
//!
//! Images are read, never written. An image can be opened from a path,
//! from bytes already in memory, or from a window at an offset inside a
//! larger file, so a consumer that embeds an image in its own binary
//! does not have to carve it out first.

#![deny(missing_docs)]
#![warn(rust_2018_idioms, unreachable_pub)]

pub mod compression;
mod error;
pub mod format;
#[cfg(feature = "read")]
pub mod fs;
#[cfg(feature = "fuse")]
pub mod fuse;
#[cfg(feature = "read")]
pub mod metadata;

pub use error::{Error, Result};
