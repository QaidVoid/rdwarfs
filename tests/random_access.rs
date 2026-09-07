//! Reading arbitrary byte ranges out of an image.

#![cfg(feature = "read")]

mod harness;

use harness::{VECTORS, vector_fs};
use rdwarfs::fs::{BlockCache, InodeKind};

/// Read a whole file through `read_into`, in `step`-sized reads.
fn read_all(fs: &rdwarfs::fs::Filesystem, inode: u32, step: usize) -> Vec<u8> {
    let cache = BlockCache::new(1 << 20);
    let size = fs.file_size(inode).expect("file size");
    let mut out = Vec::with_capacity(size as usize);
    let mut buf = vec![0u8; step];
    let mut offset = 0u64;
    while offset < size {
        let n = fs.read_into(inode, offset, &mut buf, &cache).expect("read");
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
        offset += n as u64;
    }
    out
}

fn inode_of(fs: &rdwarfs::fs::Filesystem, path: &str) -> u32 {
    fs.lookup(path.as_bytes())
        .unwrap_or_else(|e| panic!("lookup {path}: {e}"))
        .inode
}

#[test]
fn every_fixture_reads_its_files_whole() {
    for name in VECTORS {
        let fs = vector_fs(name);
        let inode = inode_of(&fs, "/top.txt");
        assert_eq!(read_all(&fs, inode, 4096), b"top level\n", "fixture {name}");
    }
}

#[test]
fn read_size_does_not_change_the_bytes() {
    let fs = vector_fs("upstream-small-blocks");
    let inode = inode_of(&fs, "/wide.bin");
    let reference = read_all(&fs, inode, 1 << 20);
    assert_eq!(reference.len(), 4096 * 512);
    for step in [1, 7, 512, 4096, 65536] {
        assert_eq!(read_all(&fs, inode, step), reference, "step {step}");
    }
}

#[test]
fn arbitrary_ranges_match_the_whole_file() {
    let fs = vector_fs("upstream-small-blocks");
    let inode = inode_of(&fs, "/wide.bin");
    let whole = read_all(&fs, inode, 1 << 20);
    let cache = BlockCache::new(1 << 20);

    for (offset, len) in [
        (0u64, 1usize),
        (1, 1),
        (511, 2),
        (4095, 4098),
        (whole.len() as u64 / 2, 12345),
        (whole.len() as u64 - 1, 1),
    ] {
        let mut buf = vec![0u8; len];
        let n = fs.read_into(inode, offset, &mut buf, &cache).expect("read");
        let end = (offset as usize + len).min(whole.len());
        assert_eq!(&buf[..n], &whole[offset as usize..end], "at {offset}+{len}");
    }
}

#[test]
fn reads_past_the_end_return_nothing() {
    let fs = vector_fs("upstream-default");
    let inode = inode_of(&fs, "/top.txt");
    let size = fs.file_size(inode).unwrap();
    let cache = BlockCache::new(1 << 20);
    let mut buf = [0u8; 64];
    assert_eq!(fs.read_into(inode, size, &mut buf, &cache).unwrap(), 0);
    assert_eq!(
        fs.read_into(inode, size + 4096, &mut buf, &cache).unwrap(),
        0
    );
}

#[test]
fn a_sparse_hole_reads_as_zeroes() {
    let fs = vector_fs("upstream-default");
    let inode = inode_of(&fs, "/sparse.bin");
    let size = fs.file_size(inode).expect("size");
    assert_eq!(size, 1 << 21, "sparse file keeps its logical size");

    let bytes = read_all(&fs, inode, 1 << 16);
    assert_eq!(bytes.len(), size as usize);
    assert!(bytes[..1 << 19].iter().all(|b| *b == 0), "leading hole");
    assert_eq!(&bytes[1 << 19..(1 << 19) + 6], b"middle");
    assert!(
        bytes[(1 << 19) + 6..].iter().all(|b| *b == 0),
        "trailing hole"
    );
}

#[test]
fn shared_content_reads_the_same_from_both_paths() {
    let fs = vector_fs("upstream-default");
    let a = read_all(&fs, inode_of(&fs, "/dup-a.txt"), 4096);
    let b = read_all(&fs, inode_of(&fs, "/dir/dup-b.txt"), 4096);
    assert_eq!(a, b"shared body\n");
    assert_eq!(a, b);
}

#[test]
fn a_hardlink_reads_the_same_bytes_as_its_target() {
    let fs = vector_fs("upstream-default");
    let target = read_all(&fs, inode_of(&fs, "/top.txt"), 4096);
    let link = read_all(&fs, inode_of(&fs, "/hardlink.txt"), 4096);
    assert_eq!(target, link);
}

#[test]
fn a_symlink_resolves_to_its_target_text() {
    let fs = vector_fs("upstream-default");
    let node = fs.lookup(b"/dir/link-to-top").expect("lookup symlink");
    assert_eq!(node.kind, InodeKind::Symlink);
    assert_eq!(fs.read_link(node.inode).unwrap(), b"../top.txt");
}

#[test]
fn borrowed_reads_agree_with_copied_reads() {
    let fs = vector_fs("upstream-small-blocks");
    let inode = inode_of(&fs, "/wide.bin");
    let whole = read_all(&fs, inode, 1 << 20);
    let mut cache = BlockCache::new(1 << 20);
    for offset in [0u64, 100, 4096, 40_000] {
        if let Some(bytes) = fs.read_borrowed(inode, offset, 64, &mut cache).unwrap() {
            assert_eq!(bytes, &whole[offset as usize..offset as usize + 64]);
        }
    }
}

#[test]
fn a_tiny_cache_still_serves_every_read() {
    let fs = vector_fs("upstream-small-blocks");
    let inode = inode_of(&fs, "/wide.bin");
    let reference = read_all(&fs, inode, 1 << 20);

    let cache = BlockCache::new(0);
    let size = fs.file_size(inode).unwrap();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 8192];
    let mut offset = 0u64;
    while offset < size {
        let n = fs.read_into(inode, offset, &mut buf, &cache).unwrap();
        out.extend_from_slice(&buf[..n]);
        offset += n as u64;
    }
    assert_eq!(out, reference, "a zero budget still serves reads");
}
