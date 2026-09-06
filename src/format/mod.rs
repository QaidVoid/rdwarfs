//! DwarFS container format: section headers, the section index, and
//! integrity hashes.
//!
//! This module covers the byte-level layout of a `.dwarfs` image
//! independently of metadata or block payload contents. It is the
//! foundation every higher-level reader builds on.
//!
//! Constants and offsets here derive from the MIT-licensed format
//! specification, `doc/dwarfs-format.md` in the DwarFS repository.
//! See PROVENANCE.md for what this implementation is and is not
//! derived from.

mod detect;
mod header;
#[cfg(feature = "read")]
pub mod history;
#[cfg(feature = "read")]
mod image;
mod index;
pub mod integrity;
mod sections;
mod source;
mod types;

pub use detect::detect_base_offset;
pub use header::{
    HEADER_LEN, MAGIC, SHA_COVER_START, SUPPORTED_MAJOR, SUPPORTED_MINOR, SectionHeader,
    WRITTEN_MINOR, XXH_COVER_START,
};
#[cfg(feature = "read")]
pub use image::{Image, SectionRecord};
pub use index::{IndexEntry, SectionIndex};
pub use sections::{SectionRef, Sections};
pub use source::{FileSource, ImageSource, WindowedSource};
pub use types::{Compression, SectionType};
