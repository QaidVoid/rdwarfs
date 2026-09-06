//! Read-side filesystem over a DwarFS image.
//!
//! [`Filesystem`] couples an [`Image`] with a parsed [`Metadata`] and
//! exposes path lookup, stat, and read operations. Inodes are
//! classified by Unix mode (`S_IFMT`); inode-type offsets are derived
//! by scanning the inode list in order, since `mkdwarfs` assigns
//! inodes strictly as directories, symlinks, unique regular files,
//! shared regular files, devices, then pipes/sockets.

// `InodeKind` and its `mode_kind` helper are needed by both the
// reader and the writer (the latter classifies source-tree entries
// before handing them to the builder). The rest of this module is
// read-side and feature-gated behind `read`.
mod inode;
pub use inode::{InodeKind, mode_kind};

#[cfg(feature = "read")]
mod read;
#[cfg(feature = "read")]
pub use read::*;
