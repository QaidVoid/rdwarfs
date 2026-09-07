//! Filesystem-level checks against the reference DwarFS image.

#![cfg(feature = "read")]

use rdwarfs::format::Image;
use rdwarfs::fs::{Filesystem, InodeKind};

const TINY: &str = "tests/vectors/tiny.dwarfs";

fn open() -> Filesystem {
    let image = Image::open(TINY).expect("open tiny image");
    Filesystem::open(image).expect("filesystem opens")
}

#[test]
fn block_size_and_inode_count_match() {
    let fs = open();
    assert_eq!(fs.block_size(), 16_777_216);
    assert_eq!(fs.inode_count(), 9);
}

#[test]
fn root_listing_matches_source_tree() {
    let fs = open();
    let root = fs.lookup(b"/").unwrap();
    assert_eq!(root.inode, 0);
    assert_eq!(root.kind, InodeKind::Directory);

    let mut entries: Vec<String> = fs
        .read_dir(root.inode)
        .unwrap()
        .into_iter()
        .map(|e| String::from_utf8(e.name).unwrap())
        .collect();
    entries.sort();
    assert_eq!(entries, vec!["a".to_string(), "b".to_string()]);
}

#[test]
fn lookup_finds_nested_paths() {
    let fs = open();
    let hello = fs.lookup(b"/a/hello.txt").unwrap();
    assert_eq!(hello.kind, InodeKind::Regular);

    let world = fs.lookup(b"/b/world.txt").unwrap();
    assert_eq!(world.kind, InodeKind::Regular);

    let deep = fs.lookup(b"/a/sub/deep.txt").unwrap();
    assert_eq!(deep.kind, InodeKind::Regular);

    let link = fs.lookup(b"/a/link").unwrap();
    assert_eq!(link.kind, InodeKind::Symlink);
}

#[test]
fn read_files_match_source_contents() {
    let fs = open();
    let hello = fs.lookup(b"/a/hello.txt").unwrap();
    let world = fs.lookup(b"/b/world.txt").unwrap();
    let deep = fs.lookup(b"/a/sub/deep.txt").unwrap();

    assert_eq!(fs.read_file(hello.inode).unwrap(), b"hello A\n");
    assert_eq!(fs.read_file(world.inode).unwrap(), b"hello B\n");
    assert_eq!(fs.read_file(deep.inode).unwrap(), b"deep file\n");
}

#[test]
fn symlink_target_matches() {
    let fs = open();
    let link = fs.lookup(b"/a/link").unwrap();
    let target = fs.read_link(link.inode).unwrap();
    assert_eq!(target, b"hello.txt");
}

#[test]
fn shared_files_resolve_to_same_content() {
    // shared.dwarfs has a/b/c.txt = "shared content" (identical, so
    // shared by mkdwarfs's dedup) and unique.txt = "different content
    // here". The reader must resolve shared inodes through
    // shared_files_table to the same chunk range.
    let image = Image::open("tests/vectors/shared.dwarfs").expect("open shared image");
    let fs = Filesystem::open(image).expect("filesystem opens");

    for name in ["a.txt", "b.txt", "c.txt"] {
        let path = format!("/{name}");
        let node = fs.lookup(path.as_bytes()).unwrap();
        assert_eq!(node.kind, InodeKind::Regular);
        let bytes = fs.read_file(node.inode).unwrap();
        assert_eq!(bytes, b"shared content");
    }

    let unique = fs.lookup(b"/unique.txt").unwrap();
    let bytes = fs.read_file(unique.inode).unwrap();
    assert_eq!(bytes, b"different content here");
}

#[test]
fn sparse_file_reconstructs_holes_as_zeros() {
    // sparse.dwarfs holds /dense.txt = "hello" (5 bytes) and
    // /sparse.bin = 4 bytes of head, ~45 KB hole, 4 bytes of tail.
    // Total reconstructed length is 50000 bytes; the head/tail are
    // "HEAD" and "TAIL" exactly.
    let image = Image::open("tests/vectors/sparse.dwarfs").expect("open sparse image");
    let fs = Filesystem::open(image).expect("filesystem opens");

    let dense = fs.lookup(b"/dense.txt").unwrap();
    assert_eq!(fs.read_file(dense.inode).unwrap(), b"hello");

    let sparse = fs.lookup(b"/sparse.bin").unwrap();
    let bytes = fs.read_file(sparse.inode).unwrap();
    assert_eq!(bytes.len(), 50_000);
    assert_eq!(&bytes[..4], b"HEAD");
    assert_eq!(&bytes[bytes.len() - 4..], b"TAIL");
    assert!(bytes[4..bytes.len() - 4].iter().all(|b| *b == 0));

    // Match the on-disk source byte-for-byte.
    let original = std::fs::read("tests/vectors/sparse.bin").unwrap();
    assert_eq!(bytes, original);
}

#[test]
fn stat_reports_modes_and_sizes() {
    let fs = open();
    let hello = fs.lookup(b"/a/hello.txt").unwrap();
    let st = fs.stat(hello.inode).unwrap();
    assert_eq!(st.kind, InodeKind::Regular);
    assert_eq!(st.size, 8); // "hello A\n"
    assert_eq!(st.mode & 0o170000, 0o100000);

    let dir = fs.lookup(b"/a").unwrap();
    let st = fs.stat(dir.inode).unwrap();
    assert_eq!(st.kind, InodeKind::Directory);
    assert_eq!(st.size, 0);
    assert_eq!(st.mode & 0o170000, 0o040000);
}

/// Built with `mkdwarfs --pack-metadata=plain`, so `names` and
/// `symlinks` are stored as plain lists rather than as compact string
/// tables. Both tables hold elements of differing length, which is what
/// exposes element-position drift.
const PLAIN: &str = "tests/vectors/plain.dwarfs";
const SHARED: &str = "tests/vectors/shared.dwarfs";

fn open_plain() -> Filesystem {
    let image = Image::open(PLAIN).expect("open plain image");
    Filesystem::open(image).expect("filesystem opens")
}

#[test]
fn plain_string_lists_decode_names_of_differing_length() {
    let fs = open_plain();
    let mut names: Vec<String> = fs
        .walk()
        .unwrap()
        .into_iter()
        .filter(|e| !e.path.is_empty())
        .map(|e| String::from_utf8(e.path).unwrap())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "/a-much-longer-symlink-name".to_string(),
            "/alpha.txt".to_string(),
            "/bravo.txt".to_string(),
            "/c.txt".to_string(),
            "/short-link".to_string(),
            "/sub".to_string(),
            "/sub/nested-name.txt".to_string(),
        ]
    );
}

#[test]
fn plain_string_lists_decode_symlinks_of_differing_length() {
    let fs = open_plain();
    let short = fs.lookup(b"/short-link").unwrap();
    assert_eq!(fs.read_link(short.inode).unwrap(), b"alpha.txt");
    let long = fs.lookup(b"/a-much-longer-symlink-name").unwrap();
    assert_eq!(fs.read_link(long.inode).unwrap(), b"sub/nested-name.txt");
}

#[test]
fn plain_string_list_file_contents_round_trip() {
    let fs = open_plain();
    let node = fs.lookup(b"/bravo.txt").unwrap();
    assert_eq!(fs.read_file(node.inode).unwrap(), b"bravo-longer\n");
}

#[test]
fn image_without_symlinks_opens_with_an_empty_symlink_table() {
    let image = Image::open(SHARED).expect("open shared image");
    let fs = Filesystem::open(image).expect("filesystem opens");
    assert!(
        !(0..fs.inode_count()).any(|i| fs.kind(i).unwrap() == InodeKind::Symlink),
        "shared.dwarfs is expected to hold no symlinks"
    );
}

/// The same tree built with `--pack-metadata=directories` and with
/// `--pack-metadata=none`. A packed table omits `parent_entry` and
/// `self_entry`, so the reader has to rebuild them.
const DIRS_PACKED: &str = "tests/vectors/dirs-packed.dwarfs";
const DIRS_PLAIN: &str = "tests/vectors/dirs-plain.dwarfs";

fn open_at(path: &str) -> Filesystem {
    let image = Image::open(path).expect("open image");
    Filesystem::open(image).expect("filesystem opens")
}

#[test]
fn packed_directories_rebuild_the_same_parents_as_unpacked() {
    let packed = open_at(DIRS_PACKED);
    let plain = open_at(DIRS_PLAIN);
    assert_eq!(packed.inode_count(), plain.inode_count());

    let mut checked = 0;
    for inode in 0..plain.inode_count() {
        if plain.kind(inode).unwrap() != InodeKind::Directory {
            continue;
        }
        assert_eq!(
            packed.parent(inode).unwrap(),
            plain.parent(inode).unwrap(),
            "parent of directory inode {inode} differs"
        );
        checked += 1;
    }
    assert!(checked >= 5, "expected several directories, saw {checked}");
}

#[test]
fn directory_parents_match_the_source_tree() {
    let fs = open_at(DIRS_PACKED);
    let root = fs.lookup(b"/").unwrap();
    assert_eq!(fs.parent(root.inode).unwrap(), root.inode);

    let a = fs.lookup(b"/a").unwrap();
    let b = fs.lookup(b"/a/b").unwrap();
    let c = fs.lookup(b"/a/b/c").unwrap();
    assert_eq!(fs.parent(a.inode).unwrap(), root.inode);
    assert_eq!(fs.parent(b.inode).unwrap(), a.inode);
    assert_eq!(fs.parent(c.inode).unwrap(), b.inode);

    let y = fs.lookup(b"/x/y").unwrap();
    let x = fs.lookup(b"/x").unwrap();
    assert_eq!(fs.parent(y.inode).unwrap(), x.inode);
}

#[test]
fn parent_of_a_non_directory_is_an_error() {
    let fs = open_at(DIRS_PLAIN);
    let file = fs.lookup(b"/top.txt").unwrap();
    assert!(fs.parent(file.inode).is_err());
}

#[test]
fn images_without_categorisation_report_no_categories() {
    let fs = open_at(DIRS_PLAIN);
    assert!(fs.category_names().is_empty());
    assert_eq!(fs.block_category(0), None);
}
