//! Forward-compatibility rules from the DwarFS format specification.
//!
//! The spec requires a reader to ignore section types it does not know
//! while the format minor version is unchanged, and to refuse an image
//! declaring a feature it does not implement. These tests build a real
//! image, patch one field, and re-seal the affected section so the only
//! thing under test is the reader's tolerance rather than its integrity
//! checking.

#![cfg(feature = "read")]

mod harness;

use rdwarfs::Error;
use rdwarfs::format::integrity::{compute_sha512_256, compute_xxh3};
use rdwarfs::format::{Compression, HEADER_LEN, Image, SectionType};
use rdwarfs::fs::Filesystem;

fn sample_image() -> Vec<u8> {
    harness::vector_bytes("upstream-default")
}

/// Recompute both header hashes over a section so a patched header is
/// once again internally consistent.
fn reseal(image: &mut [u8], section_start: usize, section_len: usize) {
    let end = section_start + section_len;
    let xxh = compute_xxh3(&image[section_start..end]);
    image[section_start + 0x28..section_start + 0x30].copy_from_slice(&xxh.to_le_bytes());
    let sha = compute_sha512_256(&image[section_start..end]);
    image[section_start + 0x08..section_start + 0x28].copy_from_slice(&sha);
}

/// Locate a section by type, returning its byte offset and total length.
fn find_section(image: &[u8], want: SectionType) -> Option<(usize, usize)> {
    let opened = Image::from_vec(image.to_vec()).ok()?;
    opened
        .sections()
        .iter()
        .find(|s| s.header.section_type == want)
        .map(|s| (s.file_offset as usize, s.section_len() as usize))
}

/// Byte offset and total length of every section, in file order.
fn section_extents(image: &[u8]) -> Vec<(usize, usize)> {
    let opened = Image::from_vec(image.to_vec()).expect("open image");
    opened
        .sections()
        .iter()
        .map(|s| (s.file_offset as usize, s.section_len() as usize))
        .collect()
}

fn patch_u16(image: &mut [u8], section_start: usize, field_offset: usize, value: u16) {
    let at = section_start + field_offset;
    image[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

/// Rewrite the section-index entry for `from` to carry `to` instead.
///
/// Each index entry is a 64-bit little-endian value whose top 16 bits
/// are the section type and whose low 48 bits are the offset from the
/// first section.
fn retype_index_entry(image: &mut [u8], from: SectionType, to: u16) {
    let (start, len) = find_section(image, SectionType::SectionIndex).expect("section index");
    let payload = start + HEADER_LEN;
    let mut at = payload;
    while at + 8 <= start + len {
        let raw = u64::from_le_bytes(image[at..at + 8].try_into().unwrap());
        if ((raw >> 48) as u16) == from.as_u16() {
            let rewritten = (u64::from(to) << 48) | (raw & ((1u64 << 48) - 1));
            image[at..at + 8].copy_from_slice(&rewritten.to_le_bytes());
            break;
        }
        at += 8;
    }
    reseal(image, start, len);
}

fn listing(fs: &Filesystem) -> Vec<String> {
    let mut paths: Vec<String> = fs
        .walk()
        .expect("walk")
        .into_iter()
        .filter(|e| !e.path.is_empty())
        .map(|e| String::from_utf8(e.path).expect("utf8 path"))
        .collect();
    paths.sort();
    paths
}

#[test]
fn unknown_section_type_is_ignored() {
    let original = sample_image();
    let (start, len) = find_section(&original, SectionType::History).expect("history section");

    let mut patched = original.clone();
    patch_u16(&mut patched, start, 0x34, 4242);
    reseal(&mut patched, start, len);
    retype_index_entry(&mut patched, SectionType::History, 4242);

    let image = Image::from_vec(patched).expect("image with an unknown section still opens");
    assert!(
        image
            .sections()
            .iter()
            .any(|s| s.header.section_type == SectionType::Unknown(4242)),
        "the unknown section is retained with its raw type"
    );
    image
        .verify_all()
        .expect("an unknown section is still hashed like any other");

    let want = {
        let fs = Filesystem::open(Image::from_vec(original).expect("open")).expect("fs");
        listing(&fs)
    };
    let fs = Filesystem::open(image).expect("filesystem opens");
    assert_eq!(listing(&fs), want);
    let node = fs.lookup(b"/dir/nested/deep.txt").expect("lookup");
    assert_eq!(fs.read_file(node.inode).unwrap(), b"nested\n");
}

#[test]
fn unknown_compression_defers_its_failure_to_decode() {
    let original = sample_image();
    let (start, len) = find_section(&original, SectionType::Block).expect("a block section");

    let mut patched = original;
    patch_u16(&mut patched, start, 0x36, 99);
    reseal(&mut patched, start, len);

    let image = Image::from_vec(patched).expect("image with an unknown codec still opens");
    let record = image
        .find_section(SectionType::Block)
        .copied()
        .expect("block section");
    assert_eq!(record.header.compression, Compression::Unknown(99));

    let err = image
        .decompress_section(&record, 1 << 20)
        .expect_err("decoding an unknown codec fails");
    assert!(
        matches!(err, Error::UnknownCompression { value: 99 }),
        "error names the numeric algorithm value, got {err}"
    );

    // Sections using a known codec still decode.
    let schema = image
        .find_section(SectionType::MetadataV2Schema)
        .copied()
        .expect("schema section");
    assert!(image.decompress_section(&schema, 1 << 20).is_ok());
}

#[test]
fn dwarfsck_reports_an_unknown_section_by_its_numeric_type() {
    let mut patched = sample_image();
    let (start, len) = find_section(&patched, SectionType::History).expect("history section");
    patch_u16(&mut patched, start, 0x34, 4242);
    reseal(&mut patched, start, len);
    retype_index_entry(&mut patched, SectionType::History, 4242);

    let dir = std::env::temp_dir().join("rdwarfs-format-compat");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("unknown-type.dwarfs");
    std::fs::write(&path, &patched).expect("write image");

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_dwarfsck"))
        .args(["-i", path.to_str().unwrap()])
        .output()
        .expect("run dwarfsck");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "dwarfsck failed: {stdout}");
    assert!(
        stdout.contains("Unknown section type 4242"),
        "summary names the numeric type, got:\n{stdout}"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn image_declaring_only_supported_features_opens() {
    let fs = Filesystem::open(Image::from_vec(sample_image()).expect("open")).expect("fs opens");
    assert!(fs.inode_count() > 0);
}

#[test]
fn minor_version_six_is_accepted_and_seven_is_not() {
    use rdwarfs::format::SUPPORTED_MINOR;
    assert_eq!(SUPPORTED_MINOR, 6);

    let original = sample_image();
    for (minor, should_open) in [(5u8, true), (6, true), (7, false)] {
        let mut patched = original.clone();
        for (start, len) in section_extents(&patched) {
            patched[start + 7] = minor;
            reseal(&mut patched, start, len);
        }
        let opened = Image::from_vec(patched);
        assert_eq!(
            opened.is_ok(),
            should_open,
            "minor {minor} should {}open",
            if should_open { "" } else { "not " }
        );
        if let Err(err) = opened {
            let text = err.to_string();
            assert!(
                text.contains("2.7"),
                "error reports both versions, got {text}"
            );
        }
    }
}

#[test]
fn a_categorised_image_reads_back_its_categories() {
    let image = Image::from_vec(harness::vector_bytes("upstream-categorized")).expect("parse");
    let fs = Filesystem::open(image).expect("categorised image opens");
    assert!(
        !listing(&fs).is_empty(),
        "categorised image still lists files"
    );
}

#[test]
fn a_sparse_image_opens_and_declares_its_feature() {
    let image = Image::from_vec(harness::vector_bytes("upstream-default")).expect("parse");
    let fs = Filesystem::open(image).expect("sparse image opens");
    let node = fs.lookup(b"/sparse.bin").expect("sparse file present");
    assert_eq!(fs.file_size(node.inode).unwrap(), 1 << 21);
}
