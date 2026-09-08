//! DwarFS metadata: Thrift schemas, Frozen2 bit-packed payload, and
//! the in-memory model the file-system reader uses.
//!
//! The METADATA_V2_SCHEMA section is Thrift compact encoded and
//! describes the bit-level layout of METADATA_V2. The METADATA_V2
//! section is then Frozen2 bit-packed per that schema: LSB-first
//! packing, optional field elision, and `distance` fields measured
//! relative to the field's own byte position (not blob-absolute).
//!
//! This module is feature-gated behind `read`.

mod bitbuf;
mod frozen;
mod fsst;
mod model;
mod schema;
pub(crate) mod thrift;

pub use bitbuf::BitBuf;
pub use frozen::{FieldView, Frozen, LayoutKind, OptionalView, Pos, RangeView};
pub use fsst::{FSST_ESC, SymTable};
pub use model::{
    Chunk, DEFAULT_LIST_CAP, DirEntry, Directory, FsOptions, InodeData, Metadata, StringTable,
};
pub use schema::{Field, Layout, Schema};
