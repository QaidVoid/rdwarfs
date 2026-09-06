//! Tar archive output for `Filesystem` contents.
//!
//! Streams a USTAR archive (via the `tar` crate) from a DwarFS image:
//! one header + payload per regular file, one header per directory or
//! symlink. Reads use the same [`BlockCache`] streaming path as the
//! FUSE mount, so even multi-gigabyte files don't have to fit in RAM
//! all at once.
//!
//! This module is feature-gated behind `read` plus `tar`.

use std::io::{self, Write};

use tar::{Builder, EntryType, Header};

use crate::Error;
use crate::fs::{BlockCache, Filesystem, InodeKind};

/// Stream `fs` as a USTAR tar archive into `writer`. Returns once
/// every entry has been written and the trailing two empty blocks
/// (end-of-archive marker) are flushed.
pub fn write_tar<W: Write>(fs: &Filesystem, writer: W) -> Result<(), Error> {
    let mut builder = Builder::new(writer);
    let entries = fs.walk()?;
    // tar walks each file sequentially, so a small working set is
    // enough. A larger budget helps when the same blocks back several
    // shared inodes.
    let mut cache = BlockCache::new(8 * fs.block_size() as usize);

    for entry in entries {
        if entry.path.is_empty() {
            // Skip the root pseudo-entry; tar archives implicitly
            // root at `.`.
            continue;
        }
        let stat = fs.stat(entry.inode)?;
        let tar_path = tar_path(&entry.path);
        let mut header = Header::new_ustar();
        header.set_mode(stat.mode & 0o7777);
        header.set_uid(u64::from(stat.uid));
        header.set_gid(u64::from(stat.gid));
        header.set_mtime(stat.mtime);

        match entry.kind {
            InodeKind::Directory => {
                header.set_entry_type(EntryType::Directory);
                header.set_size(0);
                builder
                    .append_data(&mut header, &tar_path, io::empty())
                    .map_err(map_io)?;
            }
            InodeKind::Symlink => {
                header.set_entry_type(EntryType::Symlink);
                header.set_size(0);
                let target = fs.read_link(entry.inode)?;
                header
                    .set_link_name(std::path::Path::new(
                        std::str::from_utf8(target).unwrap_or(""),
                    ))
                    .map_err(map_io)?;
                builder
                    .append_data(&mut header, &tar_path, io::empty())
                    .map_err(map_io)?;
            }
            InodeKind::Regular => {
                let size = fs.file_size(entry.inode)?;
                header.set_entry_type(EntryType::Regular);
                header.set_size(size);
                let reader = FileReader::new(fs, entry.inode, size, &mut cache);
                builder
                    .append_data(&mut header, &tar_path, reader)
                    .map_err(map_io)?;
            }
            _ => {
                // Special files (devices, FIFOs, sockets) aren't yet
                // produced by the writer side; skip them in tar
                // output too.
                continue;
            }
        }
    }

    builder.finish().map_err(map_io)?;
    builder.into_inner().map_err(map_io)?;
    Ok(())
}

/// Convert a DwarFS-internal `/`-rooted byte path to a tar-friendly
/// relative path. Leading `/` is stripped and non-UTF-8 names fall
/// back to `to_string_lossy`. Returns `"."` for the root.
fn tar_path(path: &[u8]) -> String {
    let trimmed = path.strip_prefix(b"/").unwrap_or(path);
    if trimmed.is_empty() {
        return ".".to_string();
    }
    String::from_utf8_lossy(trimmed).into_owned()
}

/// Adapter that streams `Filesystem::read_at` for one file as a
/// `Read` impl, suitable for `tar::Builder::append_data`. Bounded by
/// the file's logical size; once exhausted it returns EOF.
struct FileReader<'a> {
    fs: &'a Filesystem,
    inode: u32,
    remaining: u64,
    offset: u64,
    cache: &'a mut BlockCache,
}

impl<'a> FileReader<'a> {
    fn new(fs: &'a Filesystem, inode: u32, size: u64, cache: &'a mut BlockCache) -> Self {
        Self {
            fs,
            inode,
            remaining: size,
            offset: 0,
            cache,
        }
    }
}

impl std::io::Read for FileReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.remaining);
        let bytes = self
            .fs
            .read_at(self.inode, self.offset, want, self.cache)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let n = bytes.len();
        buf[..n].copy_from_slice(&bytes);
        self.offset += n as u64;
        self.remaining -= n as u64;
        Ok(n)
    }
}

fn map_io(err: io::Error) -> Error {
    Error::Io(err)
}
