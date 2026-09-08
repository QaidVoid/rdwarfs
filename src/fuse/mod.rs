//! FUSE adapter for the read-side filesystem.
//!
//! Maps the [`crate::fs::Filesystem`] surface onto the `fuser`
//! crate's `Filesystem` trait so a DwarFS image can be mounted
//! read-only. The mount is serialized by `fuser`'s internal
//! dispatcher; this adapter is otherwise stateless above the
//! underlying `Filesystem` reader.
//!
//! Inode mapping: FUSE expects inode 1 to be the root and rejects 0.
//! DwarFS uses 0 for the root, so this adapter applies a `+1` /
//! `-1` shift at the boundary. The shift is invisible above the
//! FUSE layer.
//!
//! This module is feature-gated behind `fuse` (which implies
//! `read`).

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    Errno, FileAttr, FileHandle, FileType, Filesystem as FuseFilesystem, FopenFlags, Generation,
    INodeNo, LockOwner, OpenFlags, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, ReplyOpen,
    Request,
};

use crate::Error;
use crate::fs::{BlockCache, Filesystem, InodeKind};

/// Default byte budget for decoded blocks held by a mount.
///
/// Bounding by bytes rather than by block count keeps the ceiling
/// independent of the image's block size, which a reader does not
/// choose. A budget smaller than the working set is a cliff rather
/// than a gentle tradeoff: random reads across an image whose blocks
/// do not all fit evict and re-decode constantly, which costs an
/// order of magnitude. Override with `-o cachesize=SIZE`.
const DEFAULT_BLOCK_CACHE_BYTES: usize = 512 * 1024 * 1024;

/// Cache lifetime hint returned to the kernel. DwarFS images are
/// strictly read-only, so we tell FUSE the metadata never changes
/// for the duration of the mount; the kernel still re-issues lookups
/// after the cache expires.
const TTL: Duration = Duration::from_secs(60);

/// Wraps a [`Filesystem`] for use as a `fuser` [`FuseFilesystem`].
pub struct DwarfsFuse {
    fs: Filesystem,
    /// Persistent block cache, shared across calls so repeated reads
    /// do not decompress the same block again. It synchronises itself,
    /// so concurrent readers neither serialize behind one lock nor
    /// decode a block more than once.
    cache: BlockCache,
}

impl DwarfsFuse {
    /// Build a FUSE wrapper around an opened DwarFS filesystem, using
    /// the default block-cache byte budget.
    pub fn new(fs: Filesystem) -> Self {
        Self::with_cache(fs, DEFAULT_BLOCK_CACHE_BYTES)
    }

    /// Build a FUSE wrapper with a specific block-cache byte budget.
    pub fn with_cache(fs: Filesystem, cache_bytes: usize) -> Self {
        Self {
            fs,
            cache: BlockCache::new(cache_bytes),
        }
    }

    /// Convert a kernel-facing FUSE inode (root = 1) to a DwarFS
    /// inode (root = 0). Returns `Err` for invalid inodes (FUSE
    /// values < 1 are reserved).
    fn dwarfs_ino(fuse_ino: INodeNo) -> Result<u32, Errno> {
        let raw: u64 = fuse_ino.into();
        if raw == 0 {
            return Err(Errno::ENOENT);
        }
        u32::try_from(raw - 1).map_err(|_| Errno::ENOENT)
    }

    fn fuse_ino(dwarfs_ino: u32) -> INodeNo {
        INodeNo(u64::from(dwarfs_ino) + 1)
    }

    fn attr_of(&self, dwarfs_ino: u32) -> Result<FileAttr, Error> {
        let stat = self.fs.stat(dwarfs_ino)?;
        let kind = file_type(stat.kind);
        let mtime = epoch_to_system_time(stat.mtime);
        let atime = epoch_to_system_time(stat.atime);
        let ctime = epoch_to_system_time(stat.ctime);
        let blocks = stat.size.div_ceil(512);
        Ok(FileAttr {
            ino: Self::fuse_ino(dwarfs_ino),
            size: stat.size,
            blocks,
            atime,
            mtime,
            ctime,
            crtime: mtime,
            kind,
            perm: (stat.mode & 0o7777) as u16,
            nlink: stat.nlink,
            uid: stat.uid,
            gid: stat.gid,
            rdev: encode_rdev(stat.rdev),
            blksize: self.fs.block_size(),
            flags: Default::default(),
        })
    }
}

/// Convert a DwarFS inode kind to the `fuser` file-type enum.
fn file_type(kind: InodeKind) -> FileType {
    match kind {
        InodeKind::Directory => FileType::Directory,
        InodeKind::Regular => FileType::RegularFile,
        InodeKind::Symlink => FileType::Symlink,
        InodeKind::BlockDevice => FileType::BlockDevice,
        InodeKind::CharDevice => FileType::CharDevice,
        InodeKind::Fifo => FileType::NamedPipe,
        InodeKind::Socket => FileType::Socket,
        // Catch-all for entries the metadata does not classify (e.g.
        // a corrupt mode bit). Surface as a regular file so the
        // mount stays navigable.
        _ => FileType::RegularFile,
    }
}

/// Encode `(major << 32) | minor` (DwarFS layout) into the
/// kernel-facing `dev_t` representation FUSE expects. We truncate to
/// 32 bits since `FileAttr::rdev` is `u32`; for the vast majority of
/// real devices this fits comfortably.
fn encode_rdev(dwarfs_rdev: u64) -> u32 {
    let major = (dwarfs_rdev >> 32) as u32;
    let minor = (dwarfs_rdev & 0xFFFF_FFFF) as u32;
    let dev = libc::makedev(major, minor);
    dev as u32
}

fn epoch_to_system_time(epoch: u64) -> SystemTime {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(epoch))
        .unwrap_or(UNIX_EPOCH)
}

impl FuseFilesystem for DwarfsFuse {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let parent_ino = match Self::dwarfs_ino(parent) {
            Ok(v) => v,
            Err(e) => {
                reply.error(e);
                return;
            }
        };
        // Search the directory rather than listing it: a listing
        // allocates a name for every entry, on every lookup, and a
        // lookup happens for each path component of every open.
        let child = match self.fs.lookup_child(parent_ino, name.as_bytes()) {
            Ok(Some(inode)) => inode,
            Ok(None) => {
                reply.error(Errno::ENOENT);
                return;
            }
            Err(_) => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        match self.attr_of(child) {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(_) => reply.error(Errno::EIO),
        }
    }

    fn open(&self, _req: &Request, _ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        // A DwarFS image is immutable, so cached pages can never go
        // stale. Without this the kernel discards a file's pages on
        // every close and re-reads them through the daemon, which
        // costs a round trip per read that the page cache could have
        // served outright.
        reply.opened(FileHandle(0), FopenFlags::FOPEN_KEEP_CACHE);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let dwarfs_ino = match Self::dwarfs_ino(ino) {
            Ok(v) => v,
            Err(e) => {
                reply.error(e);
                return;
            }
        };
        match self.attr_of(dwarfs_ino) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(_) => reply.error(Errno::ENOENT),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let dwarfs_ino = match Self::dwarfs_ino(ino) {
            Ok(v) => v,
            Err(e) => {
                reply.error(e);
                return;
            }
        };
        match self.fs.read_link(dwarfs_ino) {
            Ok(target) => reply.data(target),
            Err(_) => reply.error(Errno::EINVAL),
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let dwarfs_ino = match Self::dwarfs_ino(ino) {
            Ok(v) => v,
            Err(e) => {
                reply.error(e);
                return;
            }
        };
        // Read just the requested range. Answering out of the cache
        // rather than borrowing from it keeps the reply, which writes
        // to the FUSE device, off the cache's lock.
        let mut buf = vec![0u8; size as usize];
        match self.fs.read_into(dwarfs_ino, offset, &mut buf, &self.cache) {
            Ok(written) => reply.data(&buf[..written]),
            Err(_) => reply.error(Errno::EIO),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let dwarfs_ino = match Self::dwarfs_ino(ino) {
            Ok(v) => v,
            Err(e) => {
                reply.error(e);
                return;
            }
        };
        // Synthesize "." and ".." entries the kernel expects. The root
        // is its own parent.
        let parent_ino = self.fs.parent(dwarfs_ino).unwrap_or(dwarfs_ino);
        let mut entries: Vec<(INodeNo, FileType, Vec<u8>)> = vec![
            (
                Self::fuse_ino(dwarfs_ino),
                FileType::Directory,
                b".".to_vec(),
            ),
            (
                Self::fuse_ino(parent_ino),
                FileType::Directory,
                b"..".to_vec(),
            ),
        ];
        let listing = match self.fs.read_dir(dwarfs_ino) {
            Ok(v) => v,
            Err(_) => {
                reply.error(Errno::ENOTDIR);
                return;
            }
        };
        for l in listing {
            entries.push((Self::fuse_ino(l.inode), file_type(l.kind), l.name));
        }
        for (i, (ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            let next_offset = (i as u64) + 1;
            // `OsStr::from_bytes` accepts any byte sequence on Unix,
            // including non-UTF-8 names DwarFS may legitimately
            // store.
            let name_os = OsStr::from_bytes(&name);
            if reply.add(ino, next_offset, kind, name_os) {
                break;
            }
        }
        reply.ok();
    }
}
