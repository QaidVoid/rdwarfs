//! Extract a [`Filesystem`] tree to a destination directory.
//!
//! The extractor walks the filesystem in directory order, creating
//! directories first, then regular files, then symlinks. Shared file
//! inodes that have already been written are hard-linked instead of
//! re-extracted, so on-disk dedup mirrors the image's dedup.
//!
//! Errors abort by default; `continue_on_error` keeps going past
//! per-entry failures and returns a summary error after the walk.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::Error;
use crate::fs::{BlockCache, Filesystem, InodeKind, WalkEntry};

/// Options controlling the extractor.
#[derive(Debug, Clone, Default)]
pub struct ExtractOptions {
    /// Continue past per-entry errors instead of aborting on the first
    /// failure. The function still returns an error if at least one
    /// entry failed, so the caller can decide whether to surface it.
    pub continue_on_error: bool,
    /// When true (default behaviour), hard-link shared and hardlinked
    /// inodes on the destination filesystem instead of writing
    /// independent copies.
    pub hardlink_shared: bool,
    /// Shell-style glob patterns. When non-empty, only entries whose
    /// root-relative path matches at least one pattern are extracted.
    /// Patterns use the same syntax as the writer's `--filter`:
    /// `*` and `?` don't cross `/`, character classes like `[a-z]`
    /// are supported.
    pub include_patterns: Vec<String>,
}

impl ExtractOptions {
    /// Construct the default option set: errors abort, shared inodes
    /// hard-link, no pattern filter.
    pub fn new() -> Self {
        Self {
            continue_on_error: false,
            hardlink_shared: true,
            include_patterns: Vec::new(),
        }
    }
}

/// Borrowed view of [`ExtractOptions`] used internally so the hot
/// loop doesn't have to clone the pattern vector on every entry.
#[derive(Clone, Copy)]
struct OptionsView<'a> {
    continue_on_error: bool,
    hardlink_shared: bool,
    include_patterns: &'a [String],
}

impl<'a> OptionsView<'a> {
    fn from(options: &'a ExtractOptions) -> Self {
        Self {
            continue_on_error: options.continue_on_error,
            hardlink_shared: options.hardlink_shared,
            include_patterns: &options.include_patterns,
        }
    }

    fn matches(&self, entry: &WalkEntry) -> bool {
        if self.include_patterns.is_empty() {
            return true;
        }
        if entry.path.is_empty() {
            // Always include the synthesized root entry so the
            // destination directory is created even when only
            // sub-paths match.
            return true;
        }
        let trimmed = entry.path.strip_prefix(b"/").unwrap_or(&entry.path);
        let path_str = std::str::from_utf8(trimmed).unwrap_or("");
        // Always keep directories so the path scaffolding exists for
        // any included file. Files / symlinks must match a pattern.
        if matches!(entry.kind, InodeKind::Directory) {
            return true;
        }
        self.include_patterns
            .iter()
            .any(|p| glob_match(p, path_str))
    }
}

/// Minimal shell-style glob matcher: `*` and `?` do not cross `/`,
/// `[..]` matches a single byte in the listed set. Matches the
/// semantics used by `mkdwarfs --filter` so users can use the same
/// patterns on both ends.
fn glob_match(pattern: &str, text: &str) -> bool {
    fn go(p: &[u8], t: &[u8]) -> bool {
        if p.is_empty() {
            return t.is_empty();
        }
        match p[0] {
            b'*' => {
                for i in 0..=t.len() {
                    if t[..i].contains(&b'/') {
                        break;
                    }
                    if go(&p[1..], &t[i..]) {
                        return true;
                    }
                }
                false
            }
            b'?' => !t.is_empty() && t[0] != b'/' && go(&p[1..], &t[1..]),
            b'[' => {
                if t.is_empty() {
                    return false;
                }
                let mut end = 1;
                while end < p.len() && p[end] != b']' {
                    end += 1;
                }
                let class = &p[1..end];
                let c = t[0];
                let mut i = 0;
                let mut matched = false;
                while i < class.len() {
                    if i + 2 < class.len() && class[i + 1] == b'-' {
                        if c >= class[i] && c <= class[i + 2] {
                            matched = true;
                        }
                        i += 3;
                    } else {
                        if c == class[i] {
                            matched = true;
                        }
                        i += 1;
                    }
                }
                matched && go(&p[end + 1..], &t[1..])
            }
            byte => !t.is_empty() && byte == t[0] && go(&p[1..], &t[1..]),
        }
    }
    go(pattern.as_bytes(), text.as_bytes())
}

/// Extract every entry of `fs` under `dest`.
///
/// `dest` is created if it does not exist. Directories are created
/// recursively; regular files are written verbatim; symlinks reproduce
/// their target. Devices, FIFOs, and sockets are skipped (a future
/// extension may use `mknod`).
pub fn extract_all(
    fs: &Filesystem,
    dest: &Path,
    options: ExtractOptions,
) -> Result<ExtractStats, Error> {
    fs::create_dir_all(dest).map_err(io_error)?;
    let entries = fs.walk()?;
    let opts_view = OptionsView::from(&options);
    let filtered: Vec<&WalkEntry> = entries.iter().filter(|e| opts_view.matches(e)).collect();

    // Phase 1: create directories sequentially. The walk yields
    // parents before children, so creating in order makes nested
    // entries safe to write later.
    let mut stats = ExtractStats::default();
    let mut errors = 0usize;
    for entry in &filtered {
        if !matches!(entry.kind, InodeKind::Directory) {
            continue;
        }
        match make_directory(dest, entry) {
            Ok(_) => stats.directories += 1,
            Err(err) => {
                if opts_view.continue_on_error {
                    eprintln!(
                        "rdwarfs: skipping {}: {err}",
                        String::from_utf8_lossy(&entry.path)
                    );
                    errors += 1;
                    stats.errors += 1;
                    continue;
                }
                return Err(err);
            }
        }
    }

    // Phase 2: write each unique regular file in parallel. The
    // content_id index keeps every distinct content slot at most
    // once; subsequent files referencing the same content become
    // hardlinks in phase 3.
    let mut first_writers: Vec<&WalkEntry> = Vec::new();
    let mut seen_content: HashMap<u32, ()> = HashMap::new();
    for entry in &filtered {
        if !matches!(entry.kind, InodeKind::Regular) {
            continue;
        }
        let cid = fs.content_id(entry.inode)?;
        if seen_content.insert(cid, ()).is_none() {
            first_writers.push(entry);
        }
    }
    // Visit files in block order. A bounded cache then sees each block
    // once for a run of files rather than once per file, which is the
    // difference between decompressing a block and decompressing it
    // again for every file that lives in it.
    first_writers.sort_by_key(|e| (fs.first_block(e.inode), e.inode));

    // One cache for the whole extraction. It decodes a block once
    // however many files live in it and however many workers want it,
    // and decodes distinct blocks alongside each other.
    let cache = BlockCache::new(extract_cache_bytes(fs));
    let written_paths: Mutex<HashMap<u32, PathBuf>> = Mutex::new(HashMap::new());
    let write_one = |entry: &&WalkEntry| -> Result<u64, (Vec<u8>, Error)> {
        let target = resolve_path(dest, &entry.path);
        match write_regular(fs, entry.inode, &target, &cache) {
            Ok(bytes) => {
                let cid = match fs.content_id(entry.inode) {
                    Ok(c) => c,
                    Err(e) => return Err((entry.path.clone(), e)),
                };
                if let Ok(mut paths) = written_paths.lock() {
                    paths.insert(cid, target);
                }
                Ok(bytes)
            }
            Err(e) => Err((entry.path.clone(), e)),
        }
    };
    // Each file is written independently, so the resulting tree is the
    // same whether the writes ran on one thread or many.
    #[cfg(feature = "parallel")]
    let write_results: Vec<Result<u64, (Vec<u8>, Error)>> =
        first_writers.par_iter().map(write_one).collect();
    #[cfg(not(feature = "parallel"))]
    let write_results: Vec<Result<u64, (Vec<u8>, Error)>> =
        first_writers.iter().map(write_one).collect();
    for r in write_results {
        match r {
            Ok(_) => stats.files += 1,
            Err((path, err)) => {
                if opts_view.continue_on_error {
                    eprintln!(
                        "rdwarfs: skipping {}: {err}",
                        String::from_utf8_lossy(&path)
                    );
                    errors += 1;
                    stats.errors += 1;
                    continue;
                }
                return Err(err);
            }
        }
    }
    let mut written_paths = written_paths.into_inner().unwrap_or_default();

    // Phase 3: symlinks, hardlinks (regular files whose content_id
    // already has a writer), devices/specials/skips. Sequential and
    // cheap.
    for entry in &filtered {
        let res = match entry.kind {
            InodeKind::Directory => continue,
            InodeKind::Regular => {
                let cid = fs.content_id(entry.inode)?;
                let target = resolve_path(dest, &entry.path);
                match written_paths.get(&cid) {
                    Some(first) if first == &target => {
                        // Already written in phase 2; skip the second
                        // visit.
                        continue;
                    }
                    Some(first) if opts_view.hardlink_shared => {
                        match link_hardlink(first, &target) {
                            Ok(()) => {
                                stats.hardlinks += 1;
                                Ok(())
                            }
                            Err(e) => Err(e),
                        }
                    }
                    Some(first) => match fs::copy(first, &target) {
                        Ok(_) => {
                            stats.files += 1;
                            Ok(())
                        }
                        Err(e) => Err(io_error(e)),
                    },
                    None => {
                        // No phase-2 writer (e.g. a duplicate file
                        // race with continue_on_error); fall back to
                        // a direct extract.
                        let fallback = BlockCache::new(extract_cache_bytes(fs));
                        let bytes = write_regular(fs, entry.inode, &target, &fallback);
                        match bytes {
                            Ok(_) => {
                                written_paths.insert(cid, target);
                                stats.files += 1;
                                Ok(())
                            }
                            Err(e) => Err(e),
                        }
                    }
                }
            }
            InodeKind::Symlink => match write_symlink(fs, dest, entry) {
                Ok(()) => {
                    stats.symlinks += 1;
                    Ok(())
                }
                Err(e) => Err(e),
            },
            _ => {
                stats.skipped += 1;
                Ok(())
            }
        };
        if let Err(err) = res {
            if opts_view.continue_on_error {
                eprintln!(
                    "rdwarfs: skipping {}: {err}",
                    String::from_utf8_lossy(&entry.path)
                );
                errors += 1;
                stats.errors += 1;
                continue;
            }
            return Err(err);
        }
    }

    if errors > 0 {
        return Err(Error::Decode {
            codec: "fs-extract",
            message: format!("{errors} entries failed during extraction"),
        });
    }
    Ok(stats)
}

/// Create the directory described by `entry`. Idempotent.
fn make_directory(dest: &Path, entry: &WalkEntry) -> Result<(), Error> {
    let target = resolve_path(dest, &entry.path);
    fs::create_dir_all(&target).map_err(io_error)
}

/// Ceiling on decoded bytes an extraction keeps.
///
/// Workers run on different blocks at the same time, so a budget that
/// holds only a couple of blocks has them evicting each other and
/// decoding the same block more than once. This is a ceiling and not a
/// reservation: only blocks actually decoded are held.
const EXTRACT_CACHE_BYTES: usize = 512 << 20;

/// Never below one block, because a read has to be served from
/// somewhere.
fn extract_cache_bytes(fs: &Filesystem) -> usize {
    EXTRACT_CACHE_BYTES.max(fs.block_size() as usize)
}

/// Write a regular file from `inode` to `target`. Returns the byte
/// count actually written. Streams through the read API so big
/// files don't have to live entirely in memory at once.
fn write_regular(
    fs: &Filesystem,
    inode: u32,
    target: &Path,
    cache: &BlockCache,
) -> Result<u64, Error> {
    use std::io::Write as _;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(io_error)?;
    }
    let mut out = fs::File::create(target).map_err(io_error)?;
    let size = fs.file_size(inode)?;
    let mut buf = vec![0u8; (1 << 20).min(size.max(1) as usize)];
    let mut offset = 0u64;
    while offset < size {
        let n = fs.read_into(inode, offset, &mut buf, cache)?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n]).map_err(io_error)?;
        offset += n as u64;
    }
    Ok(size)
}

fn write_symlink(fs: &Filesystem, dest: &Path, entry: &WalkEntry) -> Result<(), Error> {
    let target = resolve_path(dest, &entry.path);
    let link_target = fs.read_link(entry.inode)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(io_error)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(link_target), &target)
            .map_err(io_error)?;
    }
    #[cfg(not(unix))]
    {
        // Symlinks on non-unix platforms require admin in some
        // configurations; surface the bytes as a regular file so the
        // tree still extracts.
        fs::write(&target, link_target).map_err(io_error)?;
    }
    Ok(())
}

fn link_hardlink(source: &Path, target: &Path) -> Result<(), Error> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(io_error)?;
    }
    fs::hard_link(source, target).map_err(io_error)
}

/// Accumulated counters returned by [`extract_all`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ExtractStats {
    /// Number of directories created.
    pub directories: u64,
    /// Number of regular files written (excluding hard links).
    pub files: u64,
    /// Number of hard links created instead of file copies.
    pub hardlinks: u64,
    /// Number of symlinks created.
    pub symlinks: u64,
    /// Number of entries skipped because the inode kind is not yet
    /// supported (devices, FIFOs, sockets).
    pub skipped: u64,
    /// Number of entries that failed when `continue_on_error` was set.
    pub errors: u64,
}

fn resolve_path(dest: &Path, rel: &[u8]) -> PathBuf {
    if rel.is_empty() {
        return dest.to_path_buf();
    }
    let trimmed = rel.strip_prefix(b"/").unwrap_or(rel);
    let mut out = dest.to_path_buf();
    out.push(byte_path(trimmed));
    out
}

#[cfg(unix)]
fn byte_path(bytes: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    PathBuf::from(std::ffi::OsStr::from_bytes(bytes))
}

#[cfg(not(unix))]
fn byte_path(bytes: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
}

fn io_error(err: io::Error) -> Error {
    Error::Io(err)
}
