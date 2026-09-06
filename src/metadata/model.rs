//! Typed lazy accessors over a Frozen2-decoded DwarFS metadata blob.
//!
//! Wraps a [`Frozen`] decoder with knowledge of `thrift/metadata.thrift`
//! field ids so callers can ask for `block_size` or `uids` directly
//! instead of routing through layout traversal. Accessors are lazy:
//! each call resolves the field's position and decodes only what was
//! asked for; nothing is materialized at construction.
//!
//! All list lengths are bounded by a caller-supplied cap to defend
//! the read path against hostile inputs.

use crate::Error;
use crate::metadata::frozen::{FieldView, Frozen, LayoutKind, Pos};
use crate::metadata::fsst::SymTable;
use crate::metadata::schema::{Layout, Schema};

/// Maximum element count accepted for any list when no explicit cap is
/// passed. 64 million entries is comfortably larger than any
/// reasonable real-world image (the upstream filesystem maxes out
/// around 16 million directory entries on a 16 GiB image) while still
/// bounding allocation on hostile inputs.
pub const DEFAULT_LIST_CAP: u64 = 64 * 1024 * 1024;

/// Field ids defined in `thrift/metadata.thrift`. Centralized so a
/// future bump in upstream ids has one obvious place to update.
#[allow(dead_code)]
mod ids {
    pub(super) const CHUNKS: i16 = 1;
    pub(super) const DIRECTORIES: i16 = 2;
    pub(super) const INODES: i16 = 3;
    pub(super) const CHUNK_TABLE: i16 = 4;
    pub(super) const SYMLINK_TABLE: i16 = 6;
    pub(super) const UIDS: i16 = 7;
    pub(super) const GIDS: i16 = 8;
    pub(super) const MODES: i16 = 9;
    pub(super) const NAMES: i16 = 10;
    pub(super) const SYMLINKS: i16 = 11;
    pub(super) const COMPACT_NAMES: i16 = 24;
    pub(super) const COMPACT_SYMLINKS: i16 = 25;
    pub(super) const TIMESTAMP_BASE: i16 = 12;
    pub(super) const BLOCK_SIZE: i16 = 15;
    pub(super) const TOTAL_FS_SIZE: i16 = 16;
    pub(super) const DEVICES: i16 = 17;
    pub(super) const OPTIONS: i16 = 18;
    pub(super) const DIR_ENTRIES: i16 = 19;
    pub(super) const SHARED_FILES_TABLE: i16 = 20;
    pub(super) const PREFERRED_PATH_SEPARATOR: i16 = 26;
    pub(super) const FEATURES: i16 = 27;
    pub(super) const CATEGORY_NAMES: i16 = 28;
    pub(super) const BLOCK_CATEGORIES: i16 = 29;
    pub(super) const HOLE_BLOCK_INDEX: i16 = 34;
    pub(super) const LARGE_HOLE_SIZE: i16 = 35;
    pub(super) const TOTAL_ALLOCATED_FS_SIZE: i16 = 36;
}

/// A chunk of file data: a (block, offset, size) view into a BLOCK
/// section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
    /// Block number (index into the array of BLOCK sections).
    pub block: u32,
    /// Byte offset of the chunk within the block.
    pub offset: u32,
    /// Byte length of the chunk.
    pub size: u32,
}

/// A directory entry: a (name, inode) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirEntry {
    /// Index into the names table.
    pub name_index: u32,
    /// Inode number this entry points at.
    pub inode_num: u32,
}

/// A directory record, indexed by inode number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Directory {
    /// Parent entry index (into `dir_entries`).
    pub parent_entry: u32,
    /// First entry of this directory in `dir_entries`. Stored
    /// delta-packed when `fs_options.packed_directories` is set; this
    /// field carries the raw value.
    pub first_entry: u32,
    /// Self entry index (v2.5+).
    pub self_entry: u32,
}

/// Filesystem-wide options recorded alongside the metadata
/// (`fs_options`). All boolean fields default to false when absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FsOptions {
    /// True when only `mtime` is stored per inode (no atime/ctime).
    pub mtime_only: bool,
    /// Time-stamp resolution in seconds. `None` falls back to 1 s.
    pub time_resolution_sec: Option<u32>,
    /// `chunk_table` is delta-packed.
    pub packed_chunk_table: bool,
    /// `directories[*].first_entry` is delta-packed.
    pub packed_directories: bool,
    /// `shared_files_table` is run-length-packed.
    pub packed_shared_files_table: bool,
    /// Sub-second resolution multiplier; `None` falls back to 1.
    pub subsecond_resolution_nsec_multiplier: Option<u32>,
    /// True when birth-time fields are populated on inodes.
    pub has_btime: bool,
    /// True when `inode_data.nlink_minus_one` carries a valid value.
    pub inodes_have_nlink: bool,
}

/// Per-inode metadata. Field ids match `thrift/metadata.thrift`.
///
/// Time offsets are relative to `metadata.timestamp_base` and scaled
/// by `fs_options.time_resolution_sec`. Subsecond parts are scaled by
/// `fs_options.subsecond_resolution_nsec_multiplier`. Both come from
/// the [`Metadata`] accessors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InodeData {
    /// Index into the modes table.
    pub mode_index: u32,
    /// Index into the uids table.
    pub owner_index: u32,
    /// Index into the gids table.
    pub group_index: u32,
    /// Access time offset.
    pub atime_offset: u64,
    /// Modification time offset.
    pub mtime_offset: u64,
    /// Status-change time offset.
    pub ctime_offset: u64,
    /// Birth (creation) time offset (v2.5+).
    pub btime_offset: u64,
    /// Sub-second part of `atime`.
    pub atime_subsec: u64,
    /// Sub-second part of `mtime`.
    pub mtime_subsec: u64,
    /// Sub-second part of `ctime`.
    pub ctime_subsec: u64,
    /// Sub-second part of `btime`.
    pub btime_subsec: u64,
    /// `nlink - 1`. Valid when `fs_options.inodes_have_nlink` is set.
    pub nlink_minus_one: u32,
}

/// Typed handle on a parsed Frozen2 metadata blob.
pub struct Metadata<'a> {
    frozen: Frozen<'a>,
    root_layout: &'a Layout,
}

impl<'a> Metadata<'a> {
    /// Build a new typed view over the given schema and decoded blob.
    pub fn parse(schema: &'a Schema, bytes: &'a [u8]) -> Result<Self, Error> {
        let root_layout = schema.root()?;
        Ok(Self {
            frozen: Frozen::new(schema, bytes),
            root_layout,
        })
    }

    /// Borrow the underlying Frozen decoder.
    pub fn frozen(&self) -> &Frozen<'a> {
        &self.frozen
    }

    /// Borrow the parsed schema.
    pub fn schema(&self) -> &Schema {
        self.frozen.schema()
    }

    /// File system block size, in bytes (root field 15).
    pub fn block_size(&self) -> Result<u32, Error> {
        let v = self.read_int(ids::BLOCK_SIZE)?;
        u32::try_from(v).map_err(|_| out_of_range("block_size", v))
    }

    /// Total uncompressed filesystem size (root field 16).
    pub fn total_fs_size(&self) -> Result<u64, Error> {
        self.read_int(ids::TOTAL_FS_SIZE)
    }

    /// Timestamp base value (root field 12). Per-inode timestamps are
    /// expressed as offsets from this value.
    pub fn timestamp_base(&self) -> Result<u64, Error> {
        self.read_int(ids::TIMESTAMP_BASE)
    }

    /// User-id table indexed by `inode.owner_index`.
    pub fn uids(&self) -> Result<Vec<u32>, Error> {
        self.read_u32_list(ids::UIDS)
    }

    /// Group-id table indexed by `inode.group_index`.
    pub fn gids(&self) -> Result<Vec<u32>, Error> {
        self.read_u32_list(ids::GIDS)
    }

    /// Inode-mode table indexed by `inode.mode_index`.
    pub fn modes(&self) -> Result<Vec<u32>, Error> {
        self.read_u32_list(ids::MODES)
    }

    /// Chunk lookup table indexed by `inode - file_inode_offset`.
    ///
    /// This is the raw, possibly delta-packed table. Unpacking happens
    /// later in the read path once `fs_options.packed_chunk_table` is
    /// inspected.
    pub fn chunk_table_raw(&self) -> Result<Vec<u32>, Error> {
        self.read_u32_list(ids::CHUNK_TABLE)
    }

    /// Symlink target lookup table (indexed by
    /// `inode - symlink_inode_offset`).
    pub fn symlink_table(&self) -> Result<Vec<u32>, Error> {
        self.read_u32_list(ids::SYMLINK_TABLE)
    }

    /// Decoded list of chunks (field 1).
    pub fn chunks(&self) -> Result<Vec<Chunk>, Error> {
        self.decode_struct_list(ids::CHUNKS, |item_layout, pos| {
            Ok(Chunk {
                block: self.read_struct_u32(pos, item_layout, 1)?,
                offset: self.read_struct_u32(pos, item_layout, 2)?,
                size: self.read_struct_u32(pos, item_layout, 3)?,
            })
        })
    }

    /// Decoded list of directory entries (field 19).
    pub fn dir_entries(&self) -> Result<Vec<DirEntry>, Error> {
        self.decode_struct_list(ids::DIR_ENTRIES, |item_layout, pos| {
            Ok(DirEntry {
                name_index: self.read_struct_u32(pos, item_layout, 1)?,
                inode_num: self.read_struct_u32(pos, item_layout, 2)?,
            })
        })
    }

    /// Shared-files table (field 20), already unpacked.
    ///
    /// The on-disk form is run-length-packed when
    /// `fs_options.packed_shared_files_table` is set: each packed
    /// entry at index `i` is the number of additional repetitions of
    /// `i` (so a packed value of `k` expands to `k + 2` copies of `i`,
    /// where `2` is the minimum repetition count). Returns an empty
    /// vector when the field is absent or unset.
    pub fn shared_files_table(&self) -> Result<Vec<u32>, Error> {
        let raw = self.read_u32_list(ids::SHARED_FILES_TABLE)?;
        if !self.fs_options()?.packed_shared_files_table {
            return Ok(raw);
        }
        let mut out = Vec::new();
        for (i, &delta) in raw.iter().enumerate() {
            let count = (delta as usize)
                .checked_add(2)
                .ok_or_else(|| out_of_range("shared_files_table run length", u64::from(delta)))?;
            let index =
                u32::try_from(i).map_err(|_| out_of_range("shared_files_table size", i as u64))?;
            out.extend(std::iter::repeat_n(index, count));
        }
        Ok(out)
    }

    /// Oversized hole lengths (field 35). Used when a hole chunk
    /// carries the sentinel `offset == block_size - 1`.
    pub fn large_hole_size(&self) -> Result<Vec<u64>, Error> {
        let values = self.read_int_list(ids::LARGE_HOLE_SIZE, 64, DEFAULT_LIST_CAP)?;
        Ok(values)
    }

    /// Filesystem options struct (field 18). Returns the default
    /// `FsOptions` when the schema lacks the field or the optional is
    /// unset.
    pub fn fs_options(&self) -> Result<FsOptions, Error> {
        let Some(view) = self.field(ids::OPTIONS) else {
            return Ok(FsOptions::default());
        };
        let outer = self.schema().layout(view.field.layout_id)?;
        let kind = LayoutKind::of(outer, self.schema())?;
        let (struct_layout, struct_pos) = match kind {
            LayoutKind::Optional { value_layout_id } => {
                let opt = self.frozen.read_optional(view.pos, outer)?;
                if !opt.present {
                    return Ok(FsOptions::default());
                }
                let Some(id) = value_layout_id else {
                    return Ok(FsOptions::default());
                };
                (self.schema().layout(id)?, opt.value_pos)
            }
            _ => (outer, view.pos),
        };

        Ok(FsOptions {
            mtime_only: self.read_struct_bool(struct_pos, struct_layout, 1)?,
            time_resolution_sec: self.read_struct_optional_u32(struct_pos, struct_layout, 2)?,
            packed_chunk_table: self.read_struct_bool(struct_pos, struct_layout, 3)?,
            packed_directories: self.read_struct_bool(struct_pos, struct_layout, 4)?,
            packed_shared_files_table: self.read_struct_bool(struct_pos, struct_layout, 5)?,
            subsecond_resolution_nsec_multiplier: self.read_struct_optional_u32(
                struct_pos,
                struct_layout,
                6,
            )?,
            has_btime: self.read_struct_bool(struct_pos, struct_layout, 7)?,
            inodes_have_nlink: self.read_struct_bool(struct_pos, struct_layout, 8)?,
        })
    }

    /// Features set declared by the writer (field 27). Each element is
    /// a short identifier such as `"sparsefiles"`. Returns an empty
    /// vector when the optional set is absent or unset.
    ///
    /// This is the canonical R1 stress case: `set<string>` lives in a
    /// range whose elements are themselves string layouts, each with a
    /// distance relative to its own element position.
    pub fn features(&self) -> Result<Vec<String>, Error> {
        self.read_optional_string_list(ids::FEATURES, "features")
    }

    /// Block category names (field 28). Indexed by the values in
    /// [`Metadata::block_categories`].
    pub fn category_names(&self) -> Result<Vec<String>, Error> {
        self.read_optional_string_list(ids::CATEGORY_NAMES, "category_names")
    }

    /// Per-block category (field 29). The index is the block number and
    /// the value indexes [`Metadata::category_names`].
    pub fn block_categories(&self) -> Result<Vec<u32>, Error> {
        let raw = self.read_int_list(ids::BLOCK_CATEGORIES, 32, DEFAULT_LIST_CAP)?;
        raw.into_iter()
            .map(|v| u32::try_from(v).map_err(|_| out_of_range("block_categories", v)))
            .collect()
    }

    /// Decode an optional root field holding a list or set of strings.
    ///
    /// Each element is itself a string layout with a distance relative
    /// to its own element position, which is what distinguishes this
    /// from a plain integral list.
    fn read_optional_string_list(
        &self,
        id: i16,
        field: &'static str,
    ) -> Result<Vec<String>, Error> {
        let Some(view) = self.field(id) else {
            return Ok(Vec::new());
        };
        let outer = self.schema().layout(view.field.layout_id)?;
        let kind = LayoutKind::of(outer, self.schema())?;
        let (list_layout, list_pos) = match kind {
            LayoutKind::Optional { value_layout_id } => {
                let opt = self.frozen.read_optional(view.pos, outer)?;
                if !opt.present {
                    return Ok(Vec::new());
                }
                let Some(id) = value_layout_id else {
                    return Ok(Vec::new());
                };
                (self.schema().layout(id)?, opt.value_pos)
            }
            _ => (outer, view.pos),
        };
        let LayoutKind::Array { item_layout_id } = LayoutKind::of(list_layout, self.schema())?
        else {
            return Err(Error::Decode {
                codec: "frozen2-model",
                message: format!("{field} (id {id}) is not a range"),
            });
        };
        let range = self.frozen.read_range(list_pos, list_layout)?;
        if range.count > DEFAULT_LIST_CAP {
            return Err(Error::CapExceeded {
                field,
                cap: DEFAULT_LIST_CAP,
                value: range.count,
            });
        }
        let item_layout = self.schema().layout(item_layout_id)?;
        let mut out = Vec::with_capacity(range.count as usize);
        for i in 0..range.count {
            let pos = self.frozen.element_pos(range, i)?;
            let bytes = self.frozen.read_string_bytes(pos, item_layout)?;
            out.push(
                std::str::from_utf8(bytes)
                    .map_err(|_| Error::Decode {
                        codec: "frozen2-model",
                        message: format!("non-utf8 string in {field}"),
                    })?
                    .to_string(),
            );
        }
        Ok(out)
    }

    /// Names table, FSST-decompressed if needed.
    ///
    /// Resolves `compact_names` (field 24) first; falls back to the
    /// plain `list<string>` at field 10 when `compact_names` is unset.
    pub fn names(&self) -> Result<Vec<Vec<u8>>, Error> {
        if let Some(table) = self.read_string_table(ids::COMPACT_NAMES)? {
            return Ok(table);
        }
        self.read_plain_string_list(ids::NAMES)
    }

    /// Symlink-targets table, FSST-decompressed if needed.
    pub fn symlinks(&self) -> Result<Vec<Vec<u8>>, Error> {
        if let Some(table) = self.read_string_table(ids::COMPACT_SYMLINKS)? {
            return Ok(table);
        }
        self.read_plain_string_list(ids::SYMLINKS)
    }

    /// Decoded list of inodes (field 3).
    pub fn inodes(&self) -> Result<Vec<InodeData>, Error> {
        self.decode_struct_list(ids::INODES, |item_layout, pos| {
            Ok(InodeData {
                mode_index: self.read_struct_u32(pos, item_layout, 2)?,
                owner_index: self.read_struct_u32(pos, item_layout, 4)?,
                group_index: self.read_struct_u32(pos, item_layout, 5)?,
                atime_offset: self.read_struct_int(pos, item_layout, 6)?,
                mtime_offset: self.read_struct_int(pos, item_layout, 7)?,
                ctime_offset: self.read_struct_int(pos, item_layout, 8)?,
                btime_offset: self.read_struct_int(pos, item_layout, 9)?,
                atime_subsec: self.read_struct_int(pos, item_layout, 10)?,
                mtime_subsec: self.read_struct_int(pos, item_layout, 11)?,
                ctime_subsec: self.read_struct_int(pos, item_layout, 12)?,
                btime_subsec: self.read_struct_int(pos, item_layout, 13)?,
                nlink_minus_one: self.read_struct_u32(pos, item_layout, 14)?,
            })
        })
    }

    /// Decoded devices table (field 17). Each entry is an encoded
    /// `(major << 32) | minor` device number, in inode order
    /// starting at `inode_offsets.device_offset`. Returns an empty
    /// vector when the field is absent.
    pub fn devices(&self) -> Result<Vec<u64>, Error> {
        let raw = self.read_int_list(ids::DEVICES, 64, DEFAULT_LIST_CAP)?;
        Ok(raw)
    }

    /// Decoded list of directories (field 2).
    ///
    /// The values are returned exactly as stored. When
    /// `fs_options.packed_directories` is set, the consumer must
    /// inclusive-prefix-sum the `first_entry` column to recover real
    /// indices.
    pub fn directories(&self) -> Result<Vec<Directory>, Error> {
        self.decode_struct_list(ids::DIRECTORIES, |item_layout, pos| {
            Ok(Directory {
                parent_entry: self.read_struct_u32(pos, item_layout, 1)?,
                first_entry: self.read_struct_u32(pos, item_layout, 2)?,
                self_entry: self.read_struct_u32(pos, item_layout, 3)?,
            })
        })
    }

    /// Optional preferred path separator code point. Returns `None`
    /// when the writer did not set the field.
    pub fn preferred_path_separator(&self) -> Result<Option<u32>, Error> {
        let Some(view) = self.field(ids::PREFERRED_PATH_SEPARATOR) else {
            return Ok(None);
        };
        let opt_layout = self.schema().layout(view.field.layout_id)?;
        let opt = self.frozen.read_optional(view.pos, opt_layout)?;
        if !opt.present {
            return Ok(None);
        }
        let Some(value_layout_id) = opt.value_layout_id else {
            return Ok(Some(0));
        };
        let value_layout = self.schema().layout(value_layout_id)?;
        let value = self
            .frozen
            .read_integral(opt.value_pos, u32::from(value_layout.bits))?;
        u32::try_from(value)
            .map(Some)
            .map_err(|_| out_of_range("preferred_path_separator", value))
    }

    /// Optional total allocated filesystem size (field 36).
    pub fn total_allocated_fs_size(&self) -> Result<Option<u64>, Error> {
        self.read_optional_int(ids::TOTAL_ALLOCATED_FS_SIZE)
    }

    /// Optional hole block index (field 34). Present whenever the
    /// image stores sparse holes.
    pub fn hole_block_index(&self) -> Result<Option<u32>, Error> {
        let Some(v) = self.read_optional_int(ids::HOLE_BLOCK_INDEX)? else {
            return Ok(None);
        };
        u32::try_from(v)
            .map(Some)
            .map_err(|_| out_of_range("hole_block_index", v))
    }

    /// Read a root integral field. Errors if the field is absent.
    fn read_int(&self, id: i16) -> Result<u64, Error> {
        let view = self.field(id).ok_or_else(|| missing_field(id))?;
        let layout = self.schema().layout(view.field.layout_id)?;
        self.frozen.read_integral(view.pos, u32::from(layout.bits))
    }

    /// Read a root `Optional<integral>` field, returning `None` when
    /// absent or unset.
    fn read_optional_int(&self, id: i16) -> Result<Option<u64>, Error> {
        let Some(view) = self.field(id) else {
            return Ok(None);
        };
        let layout = self.schema().layout(view.field.layout_id)?;
        let opt = self.frozen.read_optional(view.pos, layout)?;
        if !opt.present {
            return Ok(None);
        }
        let Some(value_layout_id) = opt.value_layout_id else {
            return Ok(Some(0));
        };
        let value_layout = self.schema().layout(value_layout_id)?;
        Ok(Some(self.frozen.read_integral(
            opt.value_pos,
            u32::from(value_layout.bits),
        )?))
    }

    /// Read a root `list<UInt32>` field with the default list cap.
    fn read_u32_list(&self, id: i16) -> Result<Vec<u32>, Error> {
        let values = self.read_int_list(id, 32, DEFAULT_LIST_CAP)?;
        let mut out = Vec::with_capacity(values.len());
        for v in values {
            out.push(u32::try_from(v).map_err(|_| Error::Decode {
                codec: "frozen2-model",
                message: format!("list element {v} does not fit in u32 (field {id})"),
            })?);
        }
        Ok(out)
    }

    /// Decode a root `list<struct>` field by calling `decoder` for
    /// every element with the per-element struct layout and position.
    /// Accepts both bare lists and `Optional<list<...>>` wrappers.
    fn decode_struct_list<T>(
        &self,
        id: i16,
        decoder: impl Fn(&Layout, Pos) -> Result<T, Error>,
    ) -> Result<Vec<T>, Error> {
        let Some((list_layout, list_pos)) = self.resolve_list(id)? else {
            return Ok(Vec::new());
        };
        let kind = LayoutKind::of(list_layout, self.schema())?;
        let LayoutKind::Array { item_layout_id } = kind else {
            return Err(Error::Decode {
                codec: "frozen2-model",
                message: format!("field {id} is not an array (kind={kind:?})"),
            });
        };
        let range = self.frozen.read_range(list_pos, list_layout)?;
        if range.count > DEFAULT_LIST_CAP {
            return Err(Error::CapExceeded {
                field: "list-count",
                cap: DEFAULT_LIST_CAP,
                value: range.count,
            });
        }
        let item_layout = self.schema().layout(item_layout_id)?;
        let mut out = Vec::with_capacity(range.count as usize);
        for i in 0..range.count {
            let pos = self.frozen.element_pos(range, i)?;
            out.push(decoder(item_layout, pos)?);
        }
        Ok(out)
    }

    /// Locate the list layout and position for a root field, unwrapping
    /// an `Optional<list<...>>` wrapper if present. Returns `None` when
    /// the field is absent in the schema or the optional is unset.
    fn resolve_list(&self, id: i16) -> Result<Option<(&Layout, Pos)>, Error> {
        let Some(view) = self.field(id) else {
            return Ok(None);
        };
        let outer = self.schema().layout(view.field.layout_id)?;
        let kind = LayoutKind::of(outer, self.schema())?;
        match kind {
            LayoutKind::Optional { value_layout_id } => {
                let opt = self.frozen.read_optional(view.pos, outer)?;
                if !opt.present {
                    return Ok(None);
                }
                let Some(id) = value_layout_id else {
                    return Ok(None);
                };
                let inner = self.schema().layout(id)?;
                Ok(Some((inner, opt.value_pos)))
            }
            _ => Ok(Some((outer, view.pos))),
        }
    }

    /// Decode an `Optional<string_table>` root field. Returns `None`
    /// when the field is absent or unset.
    fn read_string_table(&self, id: i16) -> Result<Option<Vec<Vec<u8>>>, Error> {
        let Some(view) = self.field(id) else {
            return Ok(None);
        };
        let outer = self.schema().layout(view.field.layout_id)?;
        let kind = LayoutKind::of(outer, self.schema())?;
        let LayoutKind::Optional { value_layout_id } = kind else {
            return Err(Error::Decode {
                codec: "frozen2-model",
                message: format!("field {id} is not Optional<string_table>"),
            });
        };
        let opt = self.frozen.read_optional(view.pos, outer)?;
        if !opt.present {
            return Ok(None);
        }
        let Some(value_layout_id) = value_layout_id else {
            return Ok(Some(Vec::new()));
        };
        let st_layout = self.schema().layout(value_layout_id)?;
        let st_pos = opt.value_pos;

        // string_table fields per metadata.thrift:
        //   1: string buffer
        //   2: optional string symtab
        //   3: list<UInt32> index
        //   4: bool packed_index
        let buffer = self.read_struct_string(st_pos, st_layout, 1)?;
        let symtab = self.read_struct_optional_string(st_pos, st_layout, 2)?;
        let raw_index = self.read_struct_int_list(st_pos, st_layout, 3, 32, DEFAULT_LIST_CAP)?;
        let packed = self.read_struct_bool(st_pos, st_layout, 4)?;

        let index_u32: Vec<u32> = raw_index
            .iter()
            .map(|v| {
                u32::try_from(*v).map_err(|_| Error::Decode {
                    codec: "frozen2-model",
                    message: format!("string_table index value {v} overflows u32"),
                })
            })
            .collect::<Result<_, _>>()?;

        decode_string_table(buffer, symtab, &index_u32, packed).map(Some)
    }

    /// Decode a root `list<string>` field by reading each element's
    /// string bytes via the relative-distance contract.
    fn read_plain_string_list(&self, id: i16) -> Result<Vec<Vec<u8>>, Error> {
        let Some((list_layout, list_pos)) = self.resolve_list(id)? else {
            return Ok(Vec::new());
        };
        let kind = LayoutKind::of(list_layout, self.schema())?;
        let LayoutKind::Array { item_layout_id } = kind else {
            return Err(Error::Decode {
                codec: "frozen2-model",
                message: format!("field {id} is not an array of strings"),
            });
        };
        let range = self.frozen.read_range(list_pos, list_layout)?;
        if range.count > DEFAULT_LIST_CAP {
            return Err(Error::CapExceeded {
                field: "list-count",
                cap: DEFAULT_LIST_CAP,
                value: range.count,
            });
        }
        let item_layout = self.schema().layout(item_layout_id)?;
        let mut out = Vec::with_capacity(range.count as usize);
        for i in 0..range.count {
            let pos = self.frozen.element_pos(range, i)?;
            let bytes = self.frozen.read_string_bytes(pos, item_layout)?;
            out.push(bytes.to_vec());
        }
        Ok(out)
    }

    /// Read a struct's string-typed field as raw bytes. Returns an
    /// empty slice when the field is absent.
    fn read_struct_string(
        &self,
        struct_pos: Pos,
        struct_layout: &Layout,
        field_id: i16,
    ) -> Result<&[u8], Error> {
        let Some(field) = struct_layout.field(field_id) else {
            return Ok(&[]);
        };
        let layout = self.schema().layout(field.layout_id)?;
        self.frozen
            .read_string_bytes(struct_pos.child(field), layout)
    }

    /// Read a struct's `Optional<string>` field. Returns `None` when
    /// absent or unset.
    fn read_struct_optional_string(
        &self,
        struct_pos: Pos,
        struct_layout: &Layout,
        field_id: i16,
    ) -> Result<Option<&[u8]>, Error> {
        let Some(field) = struct_layout.field(field_id) else {
            return Ok(None);
        };
        let outer = self.schema().layout(field.layout_id)?;
        let pos = struct_pos.child(field);
        match LayoutKind::of(outer, self.schema())? {
            LayoutKind::Optional { value_layout_id } => {
                let opt = self.frozen.read_optional(pos, outer)?;
                if !opt.present {
                    return Ok(None);
                }
                let Some(id) = value_layout_id else {
                    return Ok(Some(&[]));
                };
                let value_layout = self.schema().layout(id)?;
                Ok(Some(
                    self.frozen.read_string_bytes(opt.value_pos, value_layout)?,
                ))
            }
            _ => {
                // Some schemas inline the string without an Optional
                // wrapper; treat that as always-present.
                Ok(Some(self.frozen.read_string_bytes(pos, outer)?))
            }
        }
    }

    /// Read a struct field that is itself a `list<integral>`.
    /// Mirrors [`Metadata::read_int_list`] for sub-struct fields.
    fn read_struct_int_list(
        &self,
        struct_pos: Pos,
        struct_layout: &Layout,
        field_id: i16,
        _element_bits: u32,
        cap: u64,
    ) -> Result<Vec<u64>, Error> {
        let Some(field) = struct_layout.field(field_id) else {
            return Ok(Vec::new());
        };
        let list_layout = self.schema().layout(field.layout_id)?;
        let kind = LayoutKind::of(list_layout, self.schema())?;
        let range = self
            .frozen
            .read_range(struct_pos.child(field), list_layout)?;
        if range.count > cap {
            return Err(Error::CapExceeded {
                field: "list-count",
                cap,
                value: range.count,
            });
        }
        let mut out = Vec::with_capacity(range.count as usize);
        match kind {
            LayoutKind::Array { item_layout_id } => {
                let item_layout = self.schema().layout(item_layout_id)?;
                let bits = u32::from(item_layout.bits);
                if bits == 0 {
                    out.extend(std::iter::repeat_n(0u64, range.count as usize));
                } else {
                    for i in 0..range.count {
                        let pos = self.frozen.element_pos(range, i)?;
                        out.push(self.frozen.read_integral(pos, bits)?);
                    }
                }
            }
            LayoutKind::String => {
                out.extend(std::iter::repeat_n(0u64, range.count as usize));
            }
            _ => {
                return Err(Error::Decode {
                    codec: "frozen2-model",
                    message: format!("struct field {field_id} is not a list (kind={kind:?})"),
                });
            }
        }
        Ok(out)
    }

    /// Read a struct's `Optional<UInt32>` field, returning `None` when
    /// absent or unset.
    fn read_struct_optional_u32(
        &self,
        struct_pos: Pos,
        struct_layout: &Layout,
        field_id: i16,
    ) -> Result<Option<u32>, Error> {
        let Some(field) = struct_layout.field(field_id) else {
            return Ok(None);
        };
        let outer = self.schema().layout(field.layout_id)?;
        let pos = struct_pos.child(field);
        match LayoutKind::of(outer, self.schema())? {
            LayoutKind::Optional { value_layout_id } => {
                let opt = self.frozen.read_optional(pos, outer)?;
                if !opt.present {
                    return Ok(None);
                }
                let Some(id) = value_layout_id else {
                    return Ok(Some(0));
                };
                let value_layout = self.schema().layout(id)?;
                let v = self
                    .frozen
                    .read_integral(opt.value_pos, u32::from(value_layout.bits))?;
                u32::try_from(v).map(Some).map_err(|_| Error::Decode {
                    codec: "frozen2-model",
                    message: format!("optional u32 field {field_id} value {v} overflows"),
                })
            }
            _ => {
                let v = self.frozen.read_integral(pos, u32::from(outer.bits))?;
                u32::try_from(v).map(Some).map_err(|_| Error::Decode {
                    codec: "frozen2-model",
                    message: format!("u32 field {field_id} value {v} overflows"),
                })
            }
        }
    }

    /// Read a struct's boolean field. Missing fields decode as false.
    fn read_struct_bool(
        &self,
        struct_pos: Pos,
        struct_layout: &Layout,
        field_id: i16,
    ) -> Result<bool, Error> {
        let Some(field) = struct_layout.field(field_id) else {
            return Ok(false);
        };
        let layout = self.schema().layout(field.layout_id)?;
        Ok(self
            .frozen
            .read_integral(struct_pos.child(field), u32::from(layout.bits))?
            != 0)
    }

    /// Read a struct field as `u32`. Missing fields decode as zero
    /// (Frozen2 elides zero-byte fields).
    fn read_struct_u32(
        &self,
        struct_pos: Pos,
        struct_layout: &Layout,
        field_id: i16,
    ) -> Result<u32, Error> {
        let v = self.read_struct_int(struct_pos, struct_layout, field_id)?;
        u32::try_from(v).map_err(|_| Error::Decode {
            codec: "frozen2-model",
            message: format!("struct field {field_id} value {v} overflows u32"),
        })
    }

    /// Read a struct field as `u64`. Missing fields decode as zero.
    fn read_struct_int(
        &self,
        struct_pos: Pos,
        struct_layout: &Layout,
        field_id: i16,
    ) -> Result<u64, Error> {
        let Some(field) = struct_layout.field(field_id) else {
            return Ok(0);
        };
        let layout = self.schema().layout(field.layout_id)?;
        self.frozen
            .read_integral(struct_pos.child(field), u32::from(layout.bits))
    }

    /// Read a root `list<integral>` field with an explicit element
    /// width and cap. Accepts:
    /// - Bare lists and `Optional<list<...>>` wrappers.
    /// - `ArrayLayout`-encoded ranges with a per-element bit-packed
    ///   item layout. The item layout's bit width is authoritative;
    ///   items with `bits == 0` decode as zero (Frozen2 elides
    ///   storage when every value in the list is the type default).
    /// - `StringLayout`-style ranges where the writer elided field 3
    ///   (item) entirely. In that case every element is the default
    ///   value (zero).
    fn read_int_list(&self, id: i16, _element_bits: u32, cap: u64) -> Result<Vec<u64>, Error> {
        let Some((list_layout, list_pos)) = self.resolve_list(id)? else {
            return Ok(Vec::new());
        };
        let kind = LayoutKind::of(list_layout, self.schema())?;
        let range = self.frozen.read_range(list_pos, list_layout)?;
        if range.count > cap {
            return Err(Error::CapExceeded {
                field: "list-count",
                cap,
                value: range.count,
            });
        }
        let mut out = Vec::with_capacity(range.count as usize);
        match kind {
            LayoutKind::Array { item_layout_id } => {
                let item_layout = self.schema().layout(item_layout_id)?;
                if !item_layout.fields.is_empty() {
                    return Err(Error::Decode {
                        codec: "frozen2-model",
                        message: format!("field {id} elements are not integral"),
                    });
                }
                let bits = u32::from(item_layout.bits);
                if bits == 0 {
                    out.extend(std::iter::repeat_n(0u64, range.count as usize));
                } else {
                    for i in 0..range.count {
                        let pos = self.frozen.element_pos(range, i)?;
                        out.push(self.frozen.read_integral(pos, bits)?);
                    }
                }
            }
            LayoutKind::String => {
                out.extend(std::iter::repeat_n(0u64, range.count as usize));
            }
            _ => {
                return Err(Error::Decode {
                    codec: "frozen2-model",
                    message: format!("field {id} is not a list (kind={kind:?})"),
                });
            }
        }
        Ok(out)
    }

    /// Lookup a root field by id.
    fn field<'b>(&'b self, id: i16) -> Option<FieldView<'b>>
    where
        'a: 'b,
    {
        self.frozen.field(self.root_pos(), self.root_layout, id)
    }

    /// The root struct's position (byte 0, bit 0).
    fn root_pos(&self) -> Pos {
        self.frozen.root_pos()
    }
}

/// Inclusive prefix sum of a delta-packed `u32` sequence. The first
/// element is treated as the initial value; each subsequent element
/// is the difference from its predecessor.
/// Slice a `string_table` buffer into its elements.
///
/// `index` holds the offsets recorded in the table. Per the format spec
/// ("Names and Symlinks String Table Packing"), a packed index is stored
/// delta-compressed with the leading zero offset omitted, so N strings
/// are stored as N deltas and the reconstructed index has N + 1 entries.
/// When `symtab` is present each window is an independent FSST
/// bytestream that decodes to one source string, so windows are sliced
/// before they are decoded.
fn decode_string_table(
    buffer: &[u8],
    symtab: Option<&[u8]>,
    index: &[u32],
    packed: bool,
) -> Result<Vec<Vec<u8>>, Error> {
    let offsets = if packed {
        let mut out = Vec::with_capacity(index.len() + 1);
        out.push(0u32);
        out.extend(inclusive_prefix_sum_u32(index));
        out
    } else {
        index.to_vec()
    };
    if offsets.len() < 2 {
        return Ok(Vec::new());
    }

    let table = match symtab {
        Some(bytes) => Some(SymTable::parse(bytes)?.0),
        None => None,
    };
    let mut out = Vec::with_capacity(offsets.len() - 1);
    for w in offsets.windows(2) {
        let start = w[0] as usize;
        let end = w[1] as usize;
        if end < start || end > buffer.len() {
            return Err(Error::Decode {
                codec: "frozen2-model",
                message: format!(
                    "string_table slice {start}..{end} out of buffer ({} bytes)",
                    buffer.len()
                ),
            });
        }
        let slice = &buffer[start..end];
        out.push(match &table {
            Some(table) => table.decode_to_vec(slice)?,
            None => slice.to_vec(),
        });
    }
    Ok(out)
}

fn inclusive_prefix_sum_u32(deltas: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(deltas.len());
    let mut acc: u32 = 0;
    for d in deltas {
        acc = acc.wrapping_add(*d);
        out.push(acc);
    }
    out
}

fn missing_field(id: i16) -> Error {
    Error::Decode {
        codec: "frozen2-model",
        message: format!("required metadata field {id} missing"),
    }
}

fn out_of_range(name: &'static str, value: u64) -> Error {
    Error::Decode {
        codec: "frozen2-model",
        message: format!("{name} value {value} out of range for target type"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The symbol table from the format spec's FSST worked example:
    /// `["FS", "war", "!", "D"]`, so the code sequence `03 01 00 02`
    /// decodes to `DwarFS!`.
    fn spec_symtab() -> Vec<u8> {
        let mut out = vec![0x01, 0x04, 0x00, 0x00, 0x0A, 0x14, 0x34, 0x01];
        out.push(0x00);
        out.extend_from_slice(&[2, 1, 1, 0, 0, 0, 0, 0]);
        out.extend_from_slice(b"FSwar!D");
        out
    }

    fn deltas(offsets: &[u32]) -> Vec<u32> {
        offsets.windows(2).map(|w| w[1] - w[0]).collect()
    }

    #[test]
    fn packed_and_plain_indexes_agree() {
        let buffer = b"alphabravocharliedelta";
        let plain = [0u32, 5, 10, 17, 22];
        let packed = deltas(&plain);

        let want: Vec<Vec<u8>> = vec![
            b"alpha".to_vec(),
            b"bravo".to_vec(),
            b"charlie".to_vec(),
            b"delta".to_vec(),
        ];

        assert_eq!(
            decode_string_table(buffer, None, &plain, false).unwrap(),
            want
        );
        assert_eq!(
            decode_string_table(buffer, None, &packed, true).unwrap(),
            want
        );
    }

    #[test]
    fn packed_index_yields_one_string_per_delta() {
        let buffer = b"aabbbcccc";
        let packed = [1u32, 1, 3, 4];
        let decoded = decode_string_table(buffer, None, &packed, true).unwrap();
        assert_eq!(decoded.len(), packed.len());
        assert_eq!(decoded[0], b"a");
        assert_eq!(decoded[3], b"cccc");
    }

    #[test]
    fn empty_table_decodes_to_no_strings() {
        assert!(
            decode_string_table(b"", None, &[], true)
                .unwrap()
                .is_empty()
        );
        assert!(
            decode_string_table(b"", None, &[0], false)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn packed_index_with_symbol_table() {
        let symtab = spec_symtab();
        // "DwarFS!" twice, as two independently coded windows.
        let buffer = [0x03, 0x01, 0x00, 0x02, 0x03, 0x01, 0x00, 0x02];
        let plain = [0u32, 4, 8];
        let packed = deltas(&plain);

        let want: Vec<Vec<u8>> = vec![b"DwarFS!".to_vec(), b"DwarFS!".to_vec()];
        assert_eq!(
            decode_string_table(&buffer, Some(&symtab), &plain, false).unwrap(),
            want
        );
        assert_eq!(
            decode_string_table(&buffer, Some(&symtab), &packed, true).unwrap(),
            want
        );
    }

    #[test]
    fn index_past_end_of_buffer_is_rejected() {
        let err = decode_string_table(b"abc", None, &[0, 99], false).unwrap_err();
        assert!(matches!(err, Error::Decode { .. }));
    }
}
