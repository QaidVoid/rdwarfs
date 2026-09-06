//! Read-side filesystem implementation. This module is gated behind
//! the `read` feature; the public surface from `fs/mod.rs` reexports
//! everything declared here.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

use crate::Error;
use crate::format::{Image, SectionType};
use crate::metadata::{Chunk, DirEntry, Directory, FsOptions, InodeData, Metadata, Schema};

use super::{InodeKind, mode_kind};

#[path = "extract.rs"]
mod extract;
#[cfg(feature = "tar")]
#[path = "tar.rs"]
mod tar;

pub use extract::{ExtractOptions, ExtractStats, extract_all};
#[cfg(feature = "tar")]
pub use tar::write_tar;

/// Feature names this build implements.
///
/// The format spec ("Features") lets a producer record a feature set in
/// the metadata so that a reader which does not implement one of them
/// refuses the image instead of misreading it. Names come from
/// `thrift/features.thrift`.
pub const SUPPORTED_FEATURES: &[&str] = &["sparsefiles"];

/// Reject any declared feature this build does not implement.
fn check_features(features: &[String]) -> Result<(), Error> {
    match features
        .iter()
        .find(|name| !SUPPORTED_FEATURES.contains(&name.as_str()))
    {
        Some(name) => Err(Error::UnsupportedFeature { name: name.clone() }),
        None => Ok(()),
    }
}

/// Caps applied to the schema and metadata payloads during open. They
/// bound the read path against hostile compressed inputs.
const CAP_SCHEMA_BYTES: usize = 1 << 20;
const CAP_METADATA_BYTES: usize = 64 * 1024 * 1024;

/// File-type partitions over the inode table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodeOffsets {
    /// First directory inode (always 0).
    pub dir_offset: u32,
    /// First symlink inode.
    pub symlink_offset: u32,
    /// First regular-file inode (unique files start here).
    pub file_offset: u32,
    /// First shared-file inode (= `file_offset + num_unique_files`).
    pub shared_file_offset: u32,
    /// First device inode (= last regular file + 1).
    pub device_offset: u32,
    /// First pipe/socket inode.
    pub special_offset: u32,
    /// Total number of inodes.
    pub total: u32,
}

/// Per-inode stat snapshot.
#[derive(Debug, Clone, Copy)]
pub struct Stat {
    /// Inode number.
    pub inode: u32,
    /// Inode kind derived from its Unix mode.
    pub kind: InodeKind,
    /// Raw Unix mode (includes type and permission bits).
    pub mode: u32,
    /// Owner user id.
    pub uid: u32,
    /// Owning group id.
    pub gid: u32,
    /// Modification time as `timestamp_base + mtime_offset * resolution`.
    pub mtime: u64,
    /// Access time, computed the same way. Equal to `mtime` when the
    /// image records only modification times.
    pub atime: u64,
    /// Status-change time, computed the same way. Equal to `mtime`
    /// when the image records only modification times.
    pub ctime: u64,
    /// File size in bytes (0 for non-regular files).
    pub size: u64,
    /// Number of hardlinks. `1` when the image does not carry
    /// `inodes_have_nlink`; the real link count when it does.
    pub nlink: u32,
    /// Encoded `(major << 32) | minor` device number for block /
    /// character device inodes; `0` for all other kinds.
    pub rdev: u64,
}

/// A node returned by [`Filesystem::lookup`].
#[derive(Debug, Clone, Copy)]
pub struct Node {
    /// Inode number.
    pub inode: u32,
    /// Inode kind.
    pub kind: InodeKind,
}

/// One entry of a directory listing.
#[derive(Debug, Clone)]
pub struct Listing {
    /// Inode the entry points at.
    pub inode: u32,
    /// Inode kind of the target.
    pub kind: InodeKind,
    /// Entry name as raw bytes (DwarFS names are arbitrary byte
    /// sequences, not always UTF-8).
    pub name: Vec<u8>,
}

/// One node of a recursive filesystem walk. Paths are stored as
/// `/`-rooted byte sequences; the root directory is yielded as the
/// empty path before any of its children.
#[derive(Debug, Clone)]
pub struct WalkEntry {
    /// Root-relative path, starting with `/` except for the root.
    pub path: Vec<u8>,
    /// Inode number.
    pub inode: u32,
    /// Inode kind.
    pub kind: InodeKind,
}

/// Filesystem view over a DwarFS image. Construction decompresses the
/// schema and metadata sections and decodes every table needed for
/// path traversal and chunk resolution.
pub struct Filesystem {
    image: Image,
    block_records: Vec<crate::format::SectionRecord>,
    block_size: u32,
    options: FsOptions,
    timestamp_base: u64,
    modes: Vec<u32>,
    uids: Vec<u32>,
    gids: Vec<u32>,
    inodes: Vec<InodeData>,
    directories: Vec<Directory>,
    dir_entries: Vec<DirEntry>,
    chunks: Vec<Chunk>,
    /// Logical end offset of each chunk within the file that owns it,
    /// parallel to `chunks`. Lets a read find its starting chunk by
    /// binary search instead of walking the file from byte zero.
    chunk_end: Vec<u64>,
    chunk_table: Vec<u32>,
    symlink_table: Vec<u32>,
    shared_files: Vec<u32>,
    large_hole_size: Vec<u64>,
    hole_block_index: Option<u32>,
    names: Vec<Vec<u8>>,
    symlinks: Vec<Vec<u8>>,
    /// Devices table (field 17). Indexed by `inode - device_offset`,
    /// each entry is `(major << 32) | minor`. Empty when the image
    /// has no device nodes.
    devices: Vec<u64>,
    /// Category name per block index, empty when the image records no
    /// categorisation.
    block_category_names: Vec<String>,
    features: Vec<String>,
    preferred_path_separator: Option<u32>,
    total_fs_size: u64,
    total_allocated_fs_size: Option<u64>,
    offsets: InodeOffsets,
}

impl std::fmt::Debug for Filesystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Filesystem")
            .field("inodes", &self.inodes.len())
            .field("blocks", &self.block_records.len())
            .field("block_size", &self.block_size)
            .finish()
    }
}

impl Filesystem {
    /// Open a DwarFS image and decode its metadata.
    pub fn open(image: Image) -> Result<Self, Error> {
        let schema_section = image
            .find_section(SectionType::MetadataV2Schema)
            .ok_or_else(|| missing_section(SectionType::MetadataV2Schema))?;
        let metadata_section = image
            .find_section(SectionType::MetadataV2)
            .ok_or_else(|| missing_section(SectionType::MetadataV2))?;

        let schema_bytes = image.decompress_section(schema_section, CAP_SCHEMA_BYTES)?;
        let metadata_bytes = image.decompress_section(metadata_section, CAP_METADATA_BYTES)?;

        let schema = Schema::parse(&schema_bytes)?;
        let m = Metadata::parse(&schema, &metadata_bytes)?;

        let features = m.features()?;
        check_features(&features)?;

        let block_size = m.block_size()?;
        let options = m.fs_options()?;
        let timestamp_base = m.timestamp_base()?;
        let modes = m.modes()?;
        let uids = m.uids()?;
        let gids = m.gids()?;
        let inodes = m.inodes()?;
        let mut directories = m.directories()?;
        let dir_entries = m.dir_entries()?;
        let chunks = m.chunks()?;
        let mut chunk_table = m.chunk_table_raw()?;
        let symlink_table = m.symlink_table()?;
        let shared_files = m.shared_files_table()?;
        let large_hole_size = m.large_hole_size()?;
        let hole_block_index = m.hole_block_index()?;
        let names = m.names()?;
        let symlinks = m.symlinks()?;
        let devices = m.devices()?;
        let block_category_names = resolve_block_categories(&m)?;
        let preferred_path_separator = m.preferred_path_separator()?;
        let total_fs_size = m.total_fs_size()?;
        let total_allocated_fs_size = m.total_allocated_fs_size()?;

        if options.packed_chunk_table {
            chunk_table = inclusive_prefix_sum_u32(&chunk_table);
        }
        if options.packed_directories {
            unpack_directory_first_entries(&mut directories);
            rebuild_directory_links(&mut directories, &dir_entries);
        }

        let offsets = compute_offsets(&inodes, &modes, shared_files.len())?;
        let chunk_end = build_chunk_ends(
            &chunks,
            &chunk_table,
            hole_block_index,
            block_size,
            &large_hole_size,
        )?;

        let block_records = image
            .sections()
            .iter()
            .filter(|s| s.header.section_type == SectionType::Block)
            .copied()
            .collect();

        let _ = m.frozen(); // keep frame borrow scoped to construction
        let _ = metadata_bytes;
        let _ = schema_bytes;

        Ok(Self {
            image,
            block_records,
            block_size,
            options,
            timestamp_base,
            modes,
            uids,
            gids,
            inodes,
            directories,
            dir_entries,
            chunks,
            chunk_end,
            chunk_table,
            symlink_table,
            shared_files,
            large_hole_size,
            hole_block_index,
            names,
            symlinks,
            devices,
            block_category_names,
            features,
            preferred_path_separator,
            total_fs_size,
            total_allocated_fs_size,
            offsets,
        })
    }

    /// Encoded `(major << 32) | minor` device number for a device
    /// inode. Returns an error if `inode` is not a block or character
    /// device.
    pub fn device_rdev(&self, inode: u32) -> Result<u64, Error> {
        let kind = self.kind(inode)?;
        if !matches!(kind, InodeKind::BlockDevice | InodeKind::CharDevice) {
            return Err(corrupt(format!("inode {inode} is not a device")));
        }
        let idx = inode
            .checked_sub(self.offsets.device_offset)
            .ok_or_else(|| corrupt(format!("device inode {inode} precedes device offset")))?
            as usize;
        self.devices
            .get(idx)
            .copied()
            .ok_or_else(|| corrupt(format!("device index {idx} out of range")))
    }

    /// Borrow the image this filesystem reads from.
    pub fn image(&self) -> &Image {
        &self.image
    }

    /// Feature names the image declares.
    pub fn features(&self) -> &[String] {
        &self.features
    }

    /// Path separator the source filesystem preferred, when recorded.
    pub fn preferred_path_separator(&self) -> Option<u32> {
        self.preferred_path_separator
    }

    /// Total size of the original tree in bytes, as recorded.
    pub fn total_fs_size(&self) -> u64 {
        self.total_fs_size
    }

    /// Total allocated size of the original tree, when recorded. Differs
    /// from [`Filesystem::total_fs_size`] for trees with sparse files.
    pub fn total_allocated_fs_size(&self) -> Option<u64> {
        self.total_allocated_fs_size
    }

    /// Category name recorded for a block, when the image records
    /// categorisation at all.
    pub fn block_category(&self, block: u32) -> Option<&str> {
        self.block_category_names
            .get(block as usize)
            .map(String::as_str)
    }

    /// Distinct category names recorded in the image, in the order the
    /// image lists them.
    pub fn category_names(&self) -> Vec<&str> {
        let mut seen: Vec<&str> = Vec::new();
        for name in &self.block_category_names {
            if !seen.contains(&name.as_str()) {
                seen.push(name);
            }
        }
        seen
    }

    /// Block size in bytes.
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Time-stamp base value; mtime = `timestamp_base + mtime_offset * resolution`.
    pub fn timestamp_base(&self) -> u64 {
        self.timestamp_base
    }

    /// Filesystem options (packing flags, mtime-only, btime).
    pub fn options(&self) -> FsOptions {
        self.options
    }

    /// Inode-type boundaries.
    pub fn offsets(&self) -> InodeOffsets {
        self.offsets
    }

    /// Total number of inodes.
    pub fn inode_count(&self) -> u32 {
        self.offsets.total
    }

    /// Kind of an inode by number.
    pub fn kind(&self, inode: u32) -> Result<InodeKind, Error> {
        let mode = self.mode_of(inode)?;
        Ok(mode_kind(mode))
    }

    /// Stat an inode.
    pub fn stat(&self, inode: u32) -> Result<Stat, Error> {
        let i = self.inode_index(inode)?;
        let info = self.inodes[i];
        let mode = self.mode_at(info.mode_index)?;
        let kind = mode_kind(mode);
        let uid = *self
            .uids
            .get(info.owner_index as usize)
            .ok_or_else(|| corrupt(format!("uid index {} out of range", info.owner_index)))?;
        let gid = *self
            .gids
            .get(info.group_index as usize)
            .ok_or_else(|| corrupt(format!("gid index {} out of range", info.group_index)))?;
        let resolution = self.options.time_resolution_sec.unwrap_or(1) as u64;
        let at =
            |offset: u64| -> Result<u64, Error> {
                self.timestamp_base
                    .checked_add(offset.checked_mul(resolution).ok_or_else(|| {
                        corrupt("time resolution multiplication overflows".into())
                    })?)
                    .ok_or_else(|| corrupt("timestamp exceeds u64".to_string()))
            };
        let mtime = at(info.mtime_offset)?;
        // An image that records only modification times leaves the
        // other offsets at zero; report mtime rather than the epoch.
        let (atime, ctime) = if self.options.mtime_only {
            (mtime, mtime)
        } else {
            (at(info.atime_offset)?, at(info.ctime_offset)?)
        };
        let size = if kind == InodeKind::Regular {
            self.file_size(inode)?
        } else {
            0
        };
        let nlink = if self.options.inodes_have_nlink {
            info.nlink_minus_one.saturating_add(1)
        } else {
            1
        };
        let rdev = if matches!(kind, InodeKind::BlockDevice | InodeKind::CharDevice) {
            self.device_rdev(inode).unwrap_or(0)
        } else {
            0
        };
        Ok(Stat {
            inode,
            kind,
            mode,
            uid,
            gid,
            mtime,
            atime,
            ctime,
            size,
            nlink,
            rdev,
        })
    }

    /// Symlink target as raw bytes. Errors if `inode` is not a symlink.
    pub fn read_link(&self, inode: u32) -> Result<&[u8], Error> {
        if self.kind(inode)? != InodeKind::Symlink {
            return Err(corrupt(format!("inode {inode} is not a symlink")));
        }
        let slot = (inode - self.offsets.symlink_offset) as usize;
        let table_value = *self
            .symlink_table
            .get(slot)
            .ok_or_else(|| corrupt(format!("symlink_table index {slot} out of range")))?;
        self.symlinks
            .get(table_value as usize)
            .map(|s| s.as_slice())
            .ok_or_else(|| corrupt(format!("symlinks index {table_value} out of range")))
    }

    /// Total file size in bytes. Resolves through `shared_files_table`
    /// for shared files; hole chunks contribute their reconstructed
    /// length. Returns 0 for non-regular files.
    ///
    /// Constant time: the last chunk's cumulative end offset is the
    /// file size.
    pub fn file_size(&self, inode: u32) -> Result<u64, Error> {
        if self.kind(inode)? != InodeKind::Regular {
            return Ok(0);
        }
        let range = self.chunk_range(inode)?;
        match range.end.checked_sub(1) {
            Some(last) if last >= range.start => Ok(self.chunk_end[last]),
            _ => Ok(0),
        }
    }

    /// Read all bytes of a regular file into a fresh `Vec<u8>`. Hole
    /// chunks expand to zero bytes; sparse-aware callers should use
    /// [`Filesystem::read_at`] instead so the cache survives across
    /// reads.
    pub fn read_file(&self, inode: u32) -> Result<Vec<u8>, Error> {
        let size = self.file_size(inode)?;
        let cache = BlockCache::new(2 * self.block_size as usize);
        self.read_at(inode, 0, size, &cache)
    }

    /// Read up to `size` bytes from `inode` starting at `offset` into
    /// a fresh buffer.
    ///
    /// A short buffer (possibly empty) means the read ran past the end
    /// of the file. Prefer [`Filesystem::read_into`] when the caller
    /// already owns a buffer.
    pub fn read_at(
        &self,
        inode: u32,
        offset: u64,
        size: u64,
        cache: &BlockCache,
    ) -> Result<Vec<u8>, Error> {
        let available = self.file_size(inode)?.saturating_sub(offset).min(size);
        let available = usize::try_from(available)
            .map_err(|_| corrupt(format!("read of {available} bytes exceeds this platform")))?;
        let mut out = vec![0u8; available];
        let written = self.read_into(inode, offset, &mut out, cache)?;
        out.truncate(written);
        Ok(out)
    }

    /// Read from `inode` at `offset` into `buf`, returning how many
    /// bytes were written.
    ///
    /// Allocates nothing. A return value below `buf.len()` means the
    /// read reached the end of the file; the rest of `buf` is left
    /// untouched. Decoded blocks are kept in `cache` so successive
    /// reads against the same file, or any other file backed by the
    /// same blocks, do not decompress again. Chunks pointing at the
    /// hole block index expand to zero bytes.
    pub fn read_into(
        &self,
        inode: u32,
        offset: u64,
        buf: &mut [u8],
        cache: &BlockCache,
    ) -> Result<usize, Error> {
        if self.kind(inode)? != InodeKind::Regular {
            return Err(corrupt(format!("inode {inode} is not a regular file")));
        }
        let range = self.chunk_range(inode)?;
        let want_end = offset.saturating_add(buf.len() as u64);
        let mut written = 0usize;

        for i in self.chunks_covering(&range, offset) {
            if written == buf.len() {
                break;
            }
            let chunk = self.chunks[i];
            let chunk_end = self.chunk_end[i];
            let cursor = chunk_end - self.chunk_logical_len(&chunk)?;
            if cursor >= want_end {
                break;
            }
            if chunk_end <= offset {
                continue;
            }
            let local_start = offset.saturating_sub(cursor);
            let local_end = (want_end - cursor).min(chunk_end - cursor);
            let take = ((local_end - local_start) as usize).min(buf.len() - written);
            let dst = &mut buf[written..written + take];
            if self.is_hole_chunk(&chunk) {
                dst.fill(0);
            } else {
                let block_start = chunk.offset as usize + local_start as usize;
                let block_end = block_start + take;
                let block = self.decode_block(cache, chunk.block)?;
                if block_end > block.len() {
                    return Err(corrupt(format!(
                        "chunk {block_start}..{block_end} exceeds block of {} bytes",
                        block.len()
                    )));
                }
                dst.copy_from_slice(&block[block_start..block_end]);
            }
            written += take;
        }
        Ok(written)
    }

    /// Borrow `len` bytes at `offset` directly out of the block cache.
    ///
    /// Returns `Some` only when the range lies wholly inside one chunk
    /// of one block, which lets a caller hand the slice straight to a
    /// vectored write instead of copying it. Returns `None` when the
    /// range spans chunks, falls in a sparse hole, or runs past the end
    /// of the file; the caller then falls back to
    /// [`Filesystem::read_into`].
    pub fn read_borrowed<'cache>(
        &self,
        inode: u32,
        offset: u64,
        len: usize,
        cache: &'cache mut BlockCache,
    ) -> Result<Option<&'cache [u8]>, Error> {
        if self.kind(inode)? != InodeKind::Regular {
            return Err(corrupt(format!("inode {inode} is not a regular file")));
        }
        if len == 0 {
            return Ok(Some(&[]));
        }
        let range = self.chunk_range(inode)?;
        let Some(i) = self.chunks_covering(&range, offset).next() else {
            return Ok(None);
        };
        let chunk = self.chunks[i];
        if self.is_hole_chunk(&chunk) {
            return Ok(None);
        }
        let chunk_end = self.chunk_end[i];
        if offset.saturating_add(len as u64) > chunk_end {
            return Ok(None);
        }
        let cursor = chunk_end - self.chunk_logical_len(&chunk)?;
        let block_start = chunk.offset as usize + (offset - cursor) as usize;
        let block_end = block_start + len;

        let len = self.decode_block(cache, chunk.block)?.len();
        if block_end > len {
            return Err(corrupt(format!(
                "chunk {block_start}..{block_end} exceeds block of {len} bytes"
            )));
        }
        let block = cache
            .resident(chunk.block)
            .ok_or_else(|| corrupt("block cache lost entry".to_string()))?;
        Ok(Some(&block[block_start..block_end]))
    }

    /// Indices of the chunks in `range` that can contain `offset` or
    /// anything after it.
    ///
    /// `chunk_end` is monotonic within a file, so the first chunk a
    /// read touches is found by binary search rather than by walking
    /// the file from byte zero.
    fn chunks_covering(
        &self,
        range: &std::ops::Range<usize>,
        offset: u64,
    ) -> std::ops::Range<usize> {
        let ends = &self.chunk_end[range.clone()];
        let first = ends.partition_point(|end| *end <= offset);
        (range.start + first)..range.end
    }

    /// Resolve a slash-separated path to an inode. Path is interpreted
    /// as `/`-rooted regardless of leading separator. Components must
    /// not contain a `/`; pass the path as joined raw bytes.
    pub fn lookup(&self, path: &[u8]) -> Result<Node, Error> {
        let mut inode: u32 = 0;
        for component in split_path(path) {
            if component.is_empty() {
                continue;
            }
            if self.kind(inode)? != InodeKind::Directory {
                return Err(corrupt(format!(
                    "component {:?} not under directory",
                    String::from_utf8_lossy(component)
                )));
            }
            inode = self.lookup_one(inode, component)?.ok_or_else(|| {
                corrupt(format!(
                    "no entry {:?} in inode {inode}",
                    String::from_utf8_lossy(component)
                ))
            })?;
        }
        Ok(Node {
            inode,
            kind: self.kind(inode)?,
        })
    }

    /// Depth-first traversal of the filesystem, yielding every node
    /// (including the implicit root) in directory order. Directories
    /// appear before their contents; entries inside a directory are
    /// returned in the on-disk order, which `mkdwarfs` keeps sorted
    /// asciibetically.
    pub fn walk(&self) -> Result<Vec<WalkEntry>, Error> {
        let mut out = Vec::new();
        out.push(WalkEntry {
            path: Vec::new(),
            inode: 0,
            kind: self.kind(0)?,
        });
        self.walk_inner(0, &[], &mut out)?;
        Ok(out)
    }

    fn walk_inner(&self, inode: u32, prefix: &[u8], out: &mut Vec<WalkEntry>) -> Result<(), Error> {
        let entries = self.read_dir(inode)?;
        for entry in entries {
            let mut path = Vec::with_capacity(prefix.len() + 1 + entry.name.len());
            path.extend_from_slice(prefix);
            path.push(b'/');
            path.extend_from_slice(&entry.name);
            let kind = entry.kind;
            let child_inode = entry.inode;
            out.push(WalkEntry {
                path: path.clone(),
                inode: child_inode,
                kind,
            });
            if kind == InodeKind::Directory {
                self.walk_inner(child_inode, &path, out)?;
            }
        }
        Ok(())
    }

    /// Parent directory of a directory inode. The root is its own
    /// parent.
    ///
    /// `directory.parent_entry` indexes the entry that names the parent
    /// in the grandparent, so the parent's inode number is read from
    /// that entry.
    pub fn parent(&self, inode: u32) -> Result<u32, Error> {
        if self.kind(inode)? != InodeKind::Directory {
            return Err(corrupt(format!("inode {inode} is not a directory")));
        }
        let dir = self
            .directories
            .get(inode as usize)
            .ok_or_else(|| corrupt(format!("directory inode {inode} out of range")))?;
        let entry = self
            .dir_entries
            .get(dir.parent_entry as usize)
            .ok_or_else(|| corrupt(format!("parent entry {} out of range", dir.parent_entry)))?;
        Ok(entry.inode_num)
    }

    /// List the entries of a directory inode.
    pub fn read_dir(&self, inode: u32) -> Result<Vec<Listing>, Error> {
        if self.kind(inode)? != InodeKind::Directory {
            return Err(corrupt(format!("inode {inode} is not a directory")));
        }
        let (begin, end) = self.dir_entry_range(inode)?;
        let mut out = Vec::with_capacity(end - begin);
        for i in begin..end {
            let de = self.dir_entries[i];
            let name = self
                .names
                .get(de.name_index as usize)
                .ok_or_else(|| corrupt(format!("name index {} out of range", de.name_index)))?
                .clone();
            let kind = self.kind(de.inode_num)?;
            out.push(Listing {
                inode: de.inode_num,
                kind,
                name,
            });
        }
        Ok(out)
    }

    fn lookup_one(&self, dir_inode: u32, name: &[u8]) -> Result<Option<u32>, Error> {
        let (begin, end) = self.dir_entry_range(dir_inode)?;
        // dir_entries are sorted by name (asciibetically) per spec; a
        // tiny tree benefits from linear scan, large trees should
        // binary-search. Use a simple scan for now.
        for i in begin..end {
            let de = self.dir_entries[i];
            let entry_name = self
                .names
                .get(de.name_index as usize)
                .ok_or_else(|| corrupt(format!("name index {} out of range", de.name_index)))?;
            if entry_name.as_slice() == name {
                return Ok(Some(de.inode_num));
            }
        }
        Ok(None)
    }

    fn dir_entry_range(&self, dir_inode: u32) -> Result<(usize, usize), Error> {
        let i = dir_inode as usize;
        if i >= self.directories.len() {
            return Err(corrupt(format!(
                "directory inode {dir_inode} out of {} entries",
                self.directories.len()
            )));
        }
        let begin = self.directories[i].first_entry as usize;
        let end = if i + 1 < self.directories.len() {
            self.directories[i + 1].first_entry as usize
        } else {
            self.dir_entries.len()
        };
        if end > self.dir_entries.len() || begin > end {
            return Err(corrupt(format!(
                "directory entry range [{begin}, {end}) out of {} entries",
                self.dir_entries.len()
            )));
        }
        Ok((begin, end))
    }

    /// Block holding the first chunk of a regular file, when it has
    /// one. Lets a bulk reader visit files in block order so a bounded
    /// cache sees each block once instead of once per file.
    pub fn first_block(&self, inode: u32) -> Option<u32> {
        let range = self.chunk_range(inode).ok()?;
        self.chunks.get(range.start).map(|c| c.block)
    }

    /// Identity of a regular file's content for deduplication
    /// purposes. Inodes that share the same chunk range return the
    /// same value, regardless of whether they are unique or shared
    /// inodes in the DwarFS sense.
    pub fn content_id(&self, inode: u32) -> Result<u32, Error> {
        let slot = self.chunk_table_slot(inode)?;
        u32::try_from(slot).map_err(|_| corrupt(format!("content id {slot} exceeds u32")))
    }

    fn chunk_table_slot(&self, inode: u32) -> Result<usize, Error> {
        let num_unique = (self.offsets.shared_file_offset - self.offsets.file_offset) as usize;
        if inode < self.offsets.shared_file_offset {
            Ok(inode
                .checked_sub(self.offsets.file_offset)
                .ok_or_else(|| corrupt(format!("inode {inode} is not a regular file")))?
                as usize)
        } else {
            let shared_slot = (inode - self.offsets.shared_file_offset) as usize;
            let group = *self
                .shared_files
                .get(shared_slot)
                .ok_or_else(|| corrupt(format!("shared_files index {shared_slot} out of range")))?;
            num_unique
                .checked_add(group as usize)
                .ok_or_else(|| corrupt("shared file chunk index overflow".to_string()))
        }
    }

    fn chunk_range(&self, inode: u32) -> Result<std::ops::Range<usize>, Error> {
        let table_index = self.chunk_table_slot(inode)?;
        if table_index + 1 >= self.chunk_table.len() {
            return Err(corrupt(format!(
                "chunk_table index {table_index} out of range"
            )));
        }
        let start = self.chunk_table[table_index] as usize;
        let end = self.chunk_table[table_index + 1] as usize;
        if end < start || end > self.chunks.len() {
            return Err(corrupt(format!(
                "chunk range [{start}, {end}) out of {} chunks",
                self.chunks.len()
            )));
        }
        Ok(start..end)
    }

    fn hole_length(&self, chunk: &Chunk) -> Result<u64, Error> {
        hole_length(chunk, self.block_size, &self.large_hole_size)
    }

    fn is_hole_chunk(&self, chunk: &Chunk) -> bool {
        self.hole_block_index == Some(chunk.block)
    }

    /// Logical length a chunk contributes to its file.
    fn chunk_logical_len(&self, chunk: &Chunk) -> Result<u64, Error> {
        if self.is_hole_chunk(chunk) {
            self.hole_length(chunk)
        } else {
            Ok(u64::from(chunk.size))
        }
    }

    fn decode_block(&self, cache: &BlockCache, block: u32) -> Result<Arc<Vec<u8>>, Error> {
        cache.fetch(block, || {
            let record = self
                .block_records
                .get(block as usize)
                .ok_or_else(|| corrupt(format!("block {block} out of range")))?;
            self.image
                .decompress_section(record, self.block_size as usize)
        })
    }

    fn inode_index(&self, inode: u32) -> Result<usize, Error> {
        if (inode as usize) >= self.inodes.len() {
            return Err(corrupt(format!(
                "inode {inode} out of {} entries",
                self.inodes.len()
            )));
        }
        Ok(inode as usize)
    }

    fn mode_of(&self, inode: u32) -> Result<u32, Error> {
        let i = self.inode_index(inode)?;
        self.mode_at(self.inodes[i].mode_index)
    }

    fn mode_at(&self, mode_index: u32) -> Result<u32, Error> {
        self.modes
            .get(mode_index as usize)
            .copied()
            .ok_or_else(|| corrupt(format!("mode index {mode_index} out of range")))
    }
}

fn split_path(path: &[u8]) -> impl Iterator<Item = &[u8]> {
    path.split(|b| *b == b'/').filter(|s| !s.is_empty())
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

fn unpack_directory_first_entries(dirs: &mut [Directory]) {
    let mut acc: u32 = 0;
    for d in dirs.iter_mut() {
        acc = acc.wrapping_add(d.first_entry);
        d.first_entry = acc;
    }
}

/// Resolve `block_categories` against `category_names` into one name
/// per block. Empty when the image records no categorisation.
fn resolve_block_categories(m: &Metadata<'_>) -> Result<Vec<String>, Error> {
    let names = m.category_names()?;
    if names.is_empty() {
        return Ok(Vec::new());
    }
    m.block_categories()?
        .into_iter()
        .map(|index| {
            names
                .get(index as usize)
                .cloned()
                .ok_or_else(|| corrupt(format!("category index {index} out of range")))
        })
        .collect()
}

/// Rebuild the `parent_entry` and `self_entry` columns of a packed
/// directory table.
///
/// The format spec ("Directories Packing") says a packed table omits
/// both columns and that they are reconstructed by traversing
/// `dir_entries` once the `first_entry` column has been
/// delta-decompressed. `self_entry` of a directory is the index of the
/// entry naming it in its parent, and `parent_entry` is its parent's
/// `self_entry`. The root has no naming entry, so both are zero for it.
///
/// Ranges that fall outside `dir_entries` are skipped; the accessors
/// bound-check every index they use, so a corrupt table yields missing
/// links rather than a panic here.
fn rebuild_directory_links(dirs: &mut [Directory], dir_entries: &[DirEntry]) {
    let Some(dir_count) = dirs.len().checked_sub(1) else {
        return;
    };

    let entry_range = |dirs: &[Directory], d: usize| -> Option<std::ops::Range<usize>> {
        let begin = dirs[d].first_entry as usize;
        let end = dirs[d + 1].first_entry as usize;
        (begin <= end && end <= dir_entries.len()).then_some(begin..end)
    };

    let mut self_entry = vec![0u32; dir_count];
    for d in 0..dir_count {
        let Some(range) = entry_range(dirs, d) else {
            continue;
        };
        for e in range {
            let child = dir_entries[e].inode_num as usize;
            if child < dir_count && child != 0 && self_entry[child] == 0 {
                self_entry[child] = e as u32;
            }
        }
    }

    for (d, parent_self) in self_entry.iter().enumerate() {
        let Some(range) = entry_range(dirs, d) else {
            continue;
        };
        for e in range {
            let child = dir_entries[e].inode_num as usize;
            if child < dir_count && child != 0 {
                dirs[child].parent_entry = *parent_self;
            }
        }
    }

    for (d, entry) in self_entry.into_iter().enumerate() {
        dirs[d].self_entry = entry;
    }
}

/// Sentinel `chunk.offset` marking a hole whose length lives in the
/// `large_hole_size` table rather than in the chunk itself.
///
/// The format spec ("Sparse Files") describes this sentinel as
/// `BLOCK_SIZE - 1`, but every image the reference implementation
/// produces uses `u32::MAX` instead, across every block size that
/// populates the table. `BLOCK_SIZE - 1` is also a legitimate inline
/// offset, for a hole whose length leaves exactly that remainder, so
/// treating it as the sentinel misreads ordinary sparse files.
const LARGE_HOLE_SENTINEL: u32 = u32::MAX;

/// Decoded length of a hole chunk.
///
/// The length is stored as `size * block_size + offset`, unless
/// `offset` is [`LARGE_HOLE_SENTINEL`], in which case `size` indexes
/// the `large_hole_size` table.
fn hole_length(chunk: &Chunk, block_size: u32, large_hole_size: &[u64]) -> Result<u64, Error> {
    if chunk.offset == LARGE_HOLE_SENTINEL {
        let idx = chunk.size as usize;
        return large_hole_size
            .get(idx)
            .copied()
            .ok_or_else(|| corrupt(format!("large_hole_size index {idx} out of range")));
    }
    u64::from(chunk.size)
        .checked_mul(u64::from(block_size))
        .and_then(|by_blocks| by_blocks.checked_add(u64::from(chunk.offset)))
        .ok_or_else(|| corrupt("hole length overflow".to_string()))
}

/// Cumulative logical end offset of every chunk within its own file.
///
/// Chunks are grouped by file in `chunks`, with the group boundaries in
/// `chunk_table`, so one pass over the table produces a table that is
/// monotonic within each group and can be binary-searched.
fn build_chunk_ends(
    chunks: &[Chunk],
    chunk_table: &[u32],
    hole_block_index: Option<u32>,
    block_size: u32,
    large_hole_size: &[u64],
) -> Result<Vec<u64>, Error> {
    let mut ends = vec![0u64; chunks.len()];
    for slot in chunk_table.windows(2) {
        let (start, end) = (slot[0] as usize, slot[1] as usize);
        if end < start || end > chunks.len() {
            return Err(corrupt(format!(
                "chunk range [{start}, {end}) out of {} chunks",
                chunks.len()
            )));
        }
        let mut cursor: u64 = 0;
        for i in start..end {
            let chunk = &chunks[i];
            let len = if hole_block_index == Some(chunk.block) {
                hole_length(chunk, block_size, large_hole_size)?
            } else {
                u64::from(chunk.size)
            };
            cursor = cursor
                .checked_add(len)
                .ok_or_else(|| corrupt("file size overflows u64".to_string()))?;
            ends[i] = cursor;
        }
    }
    Ok(ends)
}

fn compute_offsets(
    inodes: &[InodeData],
    modes: &[u32],
    shared_files_count: usize,
) -> Result<InodeOffsets, Error> {
    let mut dir_offset = u32::MAX;
    let mut symlink_offset = u32::MAX;
    let mut file_offset = u32::MAX;
    let mut device_offset = u32::MAX;
    let mut special_offset = u32::MAX;

    for (i, inode) in inodes.iter().enumerate() {
        let mode = *modes
            .get(inode.mode_index as usize)
            .ok_or_else(|| corrupt(format!("mode index {} out of range", inode.mode_index)))?;
        let kind = mode_kind(mode);
        let idx = i as u32;
        match kind {
            InodeKind::Directory if dir_offset == u32::MAX => dir_offset = idx,
            InodeKind::Symlink if symlink_offset == u32::MAX => symlink_offset = idx,
            InodeKind::Regular if file_offset == u32::MAX => file_offset = idx,
            InodeKind::CharDevice | InodeKind::BlockDevice if device_offset == u32::MAX => {
                device_offset = idx;
            }
            InodeKind::Fifo | InodeKind::Socket if special_offset == u32::MAX => {
                special_offset = idx;
            }
            _ => {}
        }
    }

    let total = inodes.len() as u32;
    let default_to_total = |v: u32| if v == u32::MAX { total } else { v };
    let file_offset = default_to_total(file_offset).min(total);
    let device_offset = default_to_total(device_offset).min(total);
    let special_offset = default_to_total(special_offset).min(total);
    let end_of_files = device_offset.min(special_offset);
    let shared_count = u32::try_from(shared_files_count).map_err(|_| {
        corrupt(format!(
            "shared_files_count {shared_files_count} exceeds u32"
        ))
    })?;
    if file_offset
        .checked_add(shared_count)
        .map(|v| v > end_of_files)
        .unwrap_or(true)
    {
        return Err(corrupt(format!(
            "shared_files_count {shared_count} larger than the regular-file range"
        )));
    }
    let shared_file_offset = end_of_files.saturating_sub(shared_count);
    Ok(InodeOffsets {
        dir_offset: default_to_total(dir_offset).min(total),
        symlink_offset: default_to_total(symlink_offset).min(total),
        file_offset,
        shared_file_offset,
        device_offset,
        special_offset,
        total,
    })
}

fn corrupt(message: String) -> Error {
    Error::Decode {
        codec: "fs",
        message,
    }
}

fn missing_section(kind: SectionType) -> Error {
    Error::Decode {
        codec: "fs",
        message: format!("required section type {kind:?} missing"),
    }
}

/// Bounded LRU cache of decoded block payloads, keyed by block index.
///
/// Streaming consumers (FUSE, `read_at`) hand one of these to the
/// reader so a single decoded block can satisfy multiple successive
/// reads instead of paying decompression for every call. The cache
/// holds at most `budget` bytes; on overflow the least-recently-used
/// entry is evicted.
///
/// A cache may be shared by several threads. A block is decoded once
/// however many threads ask for it at the same time, and decoding one
/// block does not stop another block being decoded alongside it.
pub struct BlockCache {
    budget: usize,
    inner: Mutex<Inner>,
    /// Signalled when a block finishes decoding, successfully or not.
    decoded: Condvar,
}

#[derive(Default)]
struct Inner {
    resident: usize,
    blocks: HashMap<u32, Entry>,
    /// Resident blocks, least-recently-used first.
    order: VecDeque<u32>,
}

enum Entry {
    /// Some thread is decoding this block. Others wait rather than
    /// decoding it a second time.
    Loading,
    Ready(Arc<Vec<u8>>),
}

impl BlockCache {
    /// Build a cache holding at most `budget` bytes of decoded blocks.
    ///
    /// A budget of 0 disables caching, so every read decompresses. When
    /// a single block is larger than the whole budget it becomes the
    /// only resident entry, because a read has to be served from
    /// somewhere.
    pub fn new(budget: usize) -> Self {
        Self {
            budget,
            inner: Mutex::new(Inner::default()),
            decoded: Condvar::new(),
        }
    }

    /// Byte budget this cache was built with.
    pub fn budget(&self) -> usize {
        self.budget
    }

    /// Decoded bytes currently held.
    ///
    /// Counts published blocks only. A decode in flight holds a buffer
    /// of its own that is not resident until it is published, so peak
    /// memory can exceed the budget by one block per decoding thread.
    pub fn resident_bytes(&self) -> usize {
        self.lock().resident
    }

    /// Drop every cached block.
    ///
    /// Blocks a reader still holds stay alive until that reader is
    /// done with them.
    pub fn clear(&self) {
        let mut inner = self.lock();
        inner.blocks.retain(|_, e| matches!(e, Entry::Loading));
        inner.order.clear();
        inner.resident = 0;
    }

    /// A cache is usable after a reader panics: the entries are decoded
    /// image bytes, which a panic elsewhere cannot have invalidated.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Return `block`, decoding it with `decode` if no other thread is
    /// already doing so.
    fn fetch<F>(&self, block: u32, decode: F) -> Result<Arc<Vec<u8>>, Error>
    where
        F: FnOnce() -> Result<Vec<u8>, Error>,
    {
        let mut inner = self.lock();
        loop {
            match inner.blocks.get(&block) {
                Some(Entry::Ready(bytes)) => {
                    let bytes = Arc::clone(bytes);
                    inner.touch(block);
                    return Ok(bytes);
                }
                Some(Entry::Loading) => {
                    inner = self.decoded.wait(inner).unwrap_or_else(|e| e.into_inner());
                }
                None => break,
            }
        }
        inner.blocks.insert(block, Entry::Loading);
        drop(inner);

        // Decoding happens with the lock released, so a thread wanting
        // a different block is free to decode it at the same time.
        let in_flight = InFlight {
            cache: self,
            block,
            armed: true,
        };
        let bytes = Arc::new(decode()?);
        in_flight.publish(Arc::clone(&bytes));
        Ok(bytes)
    }

    /// Borrow a resident block. Only available to a caller holding the
    /// cache exclusively, which is what lets the bytes outlive the
    /// lock without a handle.
    fn resident(&mut self, block: u32) -> Option<&[u8]> {
        let inner = self.inner.get_mut().unwrap_or_else(|e| e.into_inner());
        inner.touch(block);
        match inner.blocks.get(&block) {
            Some(Entry::Ready(bytes)) => Some(bytes.as_slice()),
            _ => None,
        }
    }
}

impl Inner {
    fn touch(&mut self, block: u32) {
        if let Some(pos) = self.order.iter().position(|b| *b == block) {
            let key = self.order.remove(pos).expect("position is in range");
            self.order.push_back(key);
        }
    }

    fn evict_one(&mut self) -> bool {
        match self.order.pop_front() {
            Some(key) => {
                if let Some(Entry::Ready(bytes)) = self.blocks.remove(&key) {
                    self.resident -= bytes.len();
                }
                true
            }
            None => false,
        }
    }

    fn admit(&mut self, block: u32, bytes: Arc<Vec<u8>>, budget: usize) {
        if let Some(Entry::Ready(old)) = self.blocks.remove(&block) {
            self.resident -= old.len();
            if let Some(pos) = self.order.iter().position(|b| *b == block) {
                self.order.remove(pos);
            }
        }
        // Stops once the cache is empty, so a block larger than the
        // whole budget still lands and the read can be served.
        while self.resident + bytes.len() > budget && self.evict_one() {}
        self.resident += bytes.len();
        self.order.push_back(block);
        self.blocks.insert(block, Entry::Ready(bytes));
    }
}

/// Clears the in-flight marker unless the decode publishes a result, so
/// a decode that fails or panics wakes its waiters instead of leaving
/// them blocked on a block nobody is loading.
struct InFlight<'a> {
    cache: &'a BlockCache,
    block: u32,
    armed: bool,
}

impl InFlight<'_> {
    fn publish(mut self, bytes: Arc<Vec<u8>>) {
        self.armed = false;
        let mut inner = self.cache.lock();
        inner.admit(self.block, bytes, self.cache.budget);
        drop(inner);
        self.cache.decoded.notify_all();
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Left absent rather than recorded as failed: a later reader is
        // free to try the decode again.
        let mut inner = self.cache.lock();
        inner.blocks.remove(&self.block);
        drop(inner);
        self.cache.decoded.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn chunk(block: u32, offset: u32, size: u32) -> Chunk {
        Chunk {
            block,
            offset,
            size,
        }
    }

    #[test]
    fn chunk_ends_accumulate_within_each_file() {
        // Two files: the first holds three chunks, the second one.
        let chunks = vec![
            chunk(0, 0, 10),
            chunk(0, 10, 25),
            chunk(1, 0, 5),
            chunk(1, 5, 7),
        ];
        let chunk_table = vec![0u32, 3, 4];
        let ends = build_chunk_ends(&chunks, &chunk_table, None, 1 << 16, &[]).unwrap();
        assert_eq!(ends, vec![10, 35, 40, 7]);
    }

    #[test]
    fn chunk_ends_locate_the_chunk_holding_an_offset() {
        let chunks = vec![chunk(0, 0, 10), chunk(0, 10, 25), chunk(1, 0, 5)];
        let ends = build_chunk_ends(&chunks, &[0u32, 3], None, 1 << 16, &[]).unwrap();
        for (offset, want) in [(0u64, 0usize), (9, 0), (10, 1), (34, 1), (35, 2), (39, 2)] {
            assert_eq!(
                ends.partition_point(|end| *end <= offset),
                want,
                "offset {offset}"
            );
        }
        assert_eq!(
            ends.partition_point(|end| *end <= 40),
            3,
            "past end of file"
        );
    }

    #[test]
    fn chunk_ends_count_holes_by_their_reconstructed_length() {
        let block_size = 1024u32;
        // A hole of 3 blocks plus 7 bytes, then 5 bytes of data.
        let chunks = vec![chunk(9, 7, 3), chunk(0, 0, 5)];
        let ends = build_chunk_ends(&chunks, &[0u32, 2], Some(9), block_size, &[]).unwrap();
        assert_eq!(ends, vec![3 * 1024 + 7, 3 * 1024 + 7 + 5]);
    }

    fn fill(cache: &BlockCache, block: u32, size: usize) -> Arc<Vec<u8>> {
        cache
            .fetch(block, || Ok(vec![block as u8; size]))
            .expect("filling a cache block cannot fail")
    }

    fn is_resident(cache: &mut BlockCache, block: u32) -> bool {
        cache.resident(block).is_some()
    }

    #[test]
    fn block_cache_evicts_to_stay_within_its_budget() {
        let mut cache = BlockCache::new(100);
        fill(&cache, 0, 60);
        fill(&cache, 1, 30);
        assert_eq!(cache.resident_bytes(), 90);

        fill(&cache, 2, 50);
        assert!(cache.resident_bytes() <= 100, "budget respected");
        assert!(
            !is_resident(&mut cache, 0),
            "least recently used block evicted"
        );
        assert!(is_resident(&mut cache, 2));
    }

    #[test]
    fn block_cache_keeps_a_block_larger_than_its_budget() {
        let mut cache = BlockCache::new(10);
        fill(&cache, 0, 4096);
        assert!(is_resident(&mut cache, 0), "an oversize block still lands");
        assert_eq!(cache.resident_bytes(), 4096);

        fill(&cache, 1, 4);
        assert!(
            !is_resident(&mut cache, 0),
            "and is evicted by the next insert"
        );
        assert_eq!(cache.resident_bytes(), 4);
    }

    #[test]
    fn block_cache_decodes_a_block_once_for_concurrent_readers() {
        let cache = BlockCache::new(1 << 20);
        let decodes = AtomicUsize::new(0);
        let start = Barrier::new(8);

        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    start.wait();
                    let bytes = cache
                        .fetch(0, || {
                            decodes.fetch_add(1, Ordering::SeqCst);
                            std::thread::sleep(Duration::from_millis(20));
                            Ok(vec![7u8; 4096])
                        })
                        .expect("decode succeeds");
                    assert_eq!(bytes.len(), 4096);
                    assert!(bytes.iter().all(|b| *b == 7));
                });
            }
        });

        assert_eq!(
            decodes.load(Ordering::SeqCst),
            1,
            "one decode for 8 readers"
        );
    }

    #[test]
    fn block_cache_reports_a_failed_decode_to_every_waiter() {
        let cache = BlockCache::new(1 << 20);
        let start = Barrier::new(4);

        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    start.wait();
                    let outcome = cache.fetch(0, || {
                        std::thread::sleep(Duration::from_millis(20));
                        Err(corrupt("block 0 is corrupt".to_string()))
                    });
                    assert!(outcome.is_err(), "every waiter sees the failure");
                });
            }
        });

        let retried = cache.fetch(0, || Ok(vec![1u8; 8]));
        assert!(retried.is_ok(), "a failed decode is not cached");
    }

    #[test]
    fn block_cache_wakes_waiters_when_a_decode_panics() {
        let cache = BlockCache::new(1 << 20);
        let start = Barrier::new(2);

        std::thread::scope(|scope| {
            scope.spawn(|| {
                start.wait();
                // The panic unwinds out of fetch; the other thread must
                // not be left waiting on a block nobody is loading.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    cache.fetch(0, || panic!("decode panicked"))
                }));
            });
            scope.spawn(|| {
                start.wait();
                std::thread::sleep(Duration::from_millis(10));
                let bytes = cache
                    .fetch(0, || Ok(vec![3u8; 16]))
                    .expect("a later decode still succeeds");
                assert_eq!(bytes.len(), 16);
            });
        });
    }

    #[test]
    fn block_cache_stays_within_budget_under_concurrent_decodes() {
        let cache = BlockCache::new(4096);
        let start = Barrier::new(8);

        std::thread::scope(|scope| {
            for block in 0..8u32 {
                let cache = &cache;
                let start = &start;
                scope.spawn(move || {
                    start.wait();
                    for _ in 0..16 {
                        let _ = cache.fetch(block, || Ok(vec![block as u8; 1024]));
                        assert!(
                            cache.resident_bytes() <= 4096,
                            "published bytes stay within the budget"
                        );
                    }
                });
            }
        });
    }

    #[test]
    fn block_cache_entry_outlives_its_eviction() {
        let cache = BlockCache::new(1024);
        let held = fill(&cache, 0, 1024);
        fill(&cache, 1, 1024);
        assert_eq!(cache.resident_bytes(), 1024, "block 0 was evicted");
        assert!(
            held.iter().all(|b| *b == 0),
            "a reader holding an evicted block still sees its bytes"
        );
    }

    #[test]
    fn block_cache_readmitting_a_block_does_not_double_count() {
        let mut inner = Inner::default();
        inner.admit(7, Arc::new(vec![0u8; 100]), 1000);
        inner.admit(7, Arc::new(vec![0u8; 250]), 1000);
        assert_eq!(inner.resident, 250);
        assert_eq!(inner.order.len(), 1, "one queue entry per resident block");
    }

    #[test]
    fn known_features_are_accepted() {
        assert!(check_features(&[]).is_ok());
        assert!(check_features(&["sparsefiles".to_string()]).is_ok());
    }

    #[test]
    fn unknown_features_are_refused_by_name() {
        let err = check_features(&["sparsefiles".to_string(), "timetravel".to_string()])
            .expect_err("unknown feature is refused");
        match err {
            Error::UnsupportedFeature { name } => assert_eq!(name, "timetravel"),
            other => panic!("expected UnsupportedFeature, got {other}"),
        }
    }

    #[test]
    fn split_path_works() {
        let parts: Vec<&[u8]> = split_path(b"/a/b/c").collect();
        assert_eq!(parts, vec![&b"a"[..], &b"b"[..], &b"c"[..]]);
        let parts: Vec<&[u8]> = split_path(b"").collect();
        assert!(parts.is_empty());
    }
}
