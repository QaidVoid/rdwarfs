//! Reading an image through each kind of byte source.
//!
//! A source that cannot expose contiguous memory has to satisfy every
//! decode path (section headers, the section index, the schema, the
//! metadata, and block payloads) through positional reads alone. These
//! tests read the same image both ways and require identical results.

#![cfg(feature = "read")]

mod harness;

use rdwarfs::format::{FileSource, Image, ImageSource};
use rdwarfs::fs::Filesystem;

/// A fixture spanning several blocks, with a duplicate and a symlink
/// so the shared-file and symlink tables are exercised.
fn sample_image() -> Vec<u8> {
    harness::vector_bytes("upstream-small-blocks")
}

fn write_temp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("rdwarfs-image-source");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join(name);
    std::fs::write(&path, bytes).expect("write image");
    path
}

/// Every observable fact about a filesystem, so two readers can be
/// compared without listing assertions twice.
fn snapshot(fs: &Filesystem) -> Vec<(String, u64, Vec<u8>)> {
    let mut out = Vec::new();
    for entry in fs.walk().expect("walk") {
        let path = String::from_utf8(entry.path.clone()).expect("utf8 path");
        let stat = fs.stat(entry.inode).expect("stat");
        let body = match stat.kind {
            rdwarfs::fs::InodeKind::Regular => fs.read_file(entry.inode).expect("read"),
            rdwarfs::fs::InodeKind::Symlink => {
                fs.read_link(entry.inode).expect("readlink").to_vec()
            }
            _ => Vec::new(),
        };
        out.push((path, stat.size, body));
    }
    out
}

#[test]
fn positional_source_reads_identically_to_an_in_memory_source() {
    let bytes = sample_image();
    let path = write_temp("positional.dwarfs", &bytes);

    let from_memory = Filesystem::open(Image::from_vec(bytes).expect("open vec")).expect("fs");
    let source = FileSource::open(&path).expect("open file source");
    assert!(
        source.as_slice().is_none(),
        "a positional source exposes no contiguous slice"
    );
    let from_file =
        Filesystem::open(Image::from_source(source).expect("open file source")).expect("fs");

    assert_eq!(snapshot(&from_file), snapshot(&from_memory));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn positional_source_verifies_section_hashes() {
    let bytes = sample_image();
    let path = write_temp("positional-verify.dwarfs", &bytes);

    let image = Image::from_source(FileSource::open(&path).expect("source")).expect("open");
    image.verify_all().expect("fast verification");
    image.verify_deep().expect("deep verification");
    assert!(
        image.section_index().is_some(),
        "the section index is found through positional reads"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn positional_source_finds_a_prefixed_image() {
    let mut bytes = b"#!/bin/sh\nexec dwarfs \"$0\" \"$@\"\n".to_vec();
    let prefix_len = bytes.len() as u64;
    bytes.extend(sample_image());
    let path = write_temp("positional-prefixed.dwarfs", &bytes);

    let image = Image::from_source(FileSource::open(&path).expect("source")).expect("open");
    assert_eq!(image.base_offset(), prefix_len);

    let fs = Filesystem::open(image).expect("fs");
    let node = fs.lookup(b"/dir/nested/deep.txt").expect("lookup");
    assert_eq!(fs.read_file(node.inode).unwrap(), b"nested\n");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn positional_source_finds_an_image_behind_a_large_prefix() {
    // Larger than one scan chunk, so the magic is found by a probe
    // other than the first and the overlap between probes matters.
    let mut bytes = vec![0x41u8; 200 * 1024];
    let prefix_len = bytes.len() as u64;
    bytes.extend(sample_image());
    let path = write_temp("positional-large-prefix.dwarfs", &bytes);

    let image = Image::from_source(FileSource::open(&path).expect("source")).expect("open");
    assert_eq!(image.base_offset(), prefix_len);

    let _ = std::fs::remove_file(&path);
}

/// The layout onelf uses: a runtime stub, then the image, then a
/// trailing footer that locates it.
fn embed(image: &[u8], prefix_len: usize, suffix: &[u8]) -> (Vec<u8>, u64, u64) {
    let mut bytes: Vec<u8> = (0..prefix_len).map(|i| (i % 256) as u8).collect();
    let offset = bytes.len() as u64;
    bytes.extend_from_slice(image);
    let len = image.len() as u64;
    bytes.extend_from_slice(suffix);
    (bytes, offset, len)
}

#[test]
fn image_with_trailing_bytes_opens_through_a_window() {
    let image = sample_image();
    let (embedded, offset, len) = embed(&image, 100_000, b"ONELF-FOOTER-TRAILING-DATA");

    // Without a window the trailing bytes look like a truncated section.
    assert!(
        Image::from_vec(embedded.clone()).is_err(),
        "an unwindowed open cannot know where the image ends"
    );

    let windowed = Image::from_window(embedded, offset, len).expect("windowed open");
    windowed.verify_all().expect("verification");
    assert!(windowed.section_index().is_some());

    let want = Filesystem::open(Image::from_vec(image).expect("open")).expect("fs");
    let got = Filesystem::open(windowed).expect("fs");
    assert_eq!(snapshot(&got), snapshot(&want));
}

#[test]
fn windowed_open_works_over_a_positional_source() {
    let image = sample_image();
    let (embedded, offset, len) = embed(&image, 70_000, b"trailing footer bytes");
    let path = write_temp("windowed-positional.dwarfs", &embedded);

    let source = FileSource::open(&path).expect("source");
    let windowed = Image::from_window(source, offset, len).expect("windowed open");
    let got = Filesystem::open(windowed).expect("fs");
    let want = Filesystem::open(Image::from_vec(image).expect("open")).expect("fs");
    assert_eq!(snapshot(&got), snapshot(&want));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn window_offsets_are_relative_to_the_window() {
    let image = sample_image();
    let bare = Image::from_vec(image.clone()).expect("open");
    let bare_offsets: Vec<u64> = bare.sections().iter().map(|s| s.file_offset).collect();

    let (embedded, offset, len) = embed(&image, 4096, b"tail");
    let windowed = Image::from_window(embedded, offset, len).expect("windowed open");
    let windowed_offsets: Vec<u64> = windowed.sections().iter().map(|s| s.file_offset).collect();

    assert_eq!(windowed_offsets, bare_offsets);
    assert_eq!(windowed.len(), len);
}

#[test]
fn a_window_past_the_end_of_the_source_is_refused() {
    let image = sample_image();
    let len = image.len() as u64;
    let err = Image::from_window(image, 16, len).expect_err("window overruns the source");
    match err {
        rdwarfs::Error::SourceOutOfBounds {
            offset,
            len: want,
            source_len,
        } => {
            assert_eq!(offset, 16);
            assert_eq!(want, len);
            assert_eq!(source_len, len);
        }
        other => panic!("expected SourceOutOfBounds, got {other}"),
    }
}
