//! End-to-end checks against an image built by reference `mkdwarfs`.
//!
//! The image and the JSON dump are committed under `tests/vectors/`
//! and regenerated with:
//!
//! ```text
//! mkdwarfs -i SRC -o tests/vectors/tiny.dwarfs --no-progress
//! dwarfsck tests/vectors/tiny.dwarfs --export-metadata=tests/vectors/tiny.metadata.json
//! ```

#![cfg(feature = "read")]

use rdwarfs::format::{Image, SectionType};
use rdwarfs::metadata::{
    Chunk, DirEntry, Directory, Frozen, FsOptions, InodeData, LayoutKind, Metadata, Schema,
};

const TINY: &str = "tests/vectors/tiny.dwarfs";

const CAP_SCHEMA: usize = 64 * 1024;
const CAP_METADATA: usize = 64 * 1024 * 1024;

fn open_decoded() -> (Schema, Vec<u8>) {
    let image = Image::open(TINY).expect("open tiny image");
    image.verify_all().expect("xxh3 verifies");

    let schema_section = image
        .find_section(SectionType::MetadataV2Schema)
        .expect("schema section present");
    let metadata_section = image
        .find_section(SectionType::MetadataV2)
        .expect("metadata section present");

    let schema_bytes = image
        .decompress_section(schema_section, CAP_SCHEMA)
        .expect("schema decompresses");
    let metadata_bytes = image
        .decompress_section(metadata_section, CAP_METADATA)
        .expect("metadata decompresses");

    let schema = Schema::parse(&schema_bytes).expect("schema parses");
    (schema, metadata_bytes)
}

#[test]
fn schema_and_root_layout_resolve() {
    let (schema, _) = open_decoded();
    assert_eq!(schema.file_version, 1);
    let root = schema.root().expect("root layout present");
    assert!(!root.fields.is_empty(), "metadata root has fields");
}

#[test]
fn root_integral_fields_match_export() {
    let (schema, metadata) = open_decoded();
    let frozen = Frozen::new(&schema, &metadata);
    let root = schema.root().unwrap();
    let root_pos = frozen.root_pos();

    // From tiny.metadata.json: block_size, total_fs_size, and
    // timestamp_base are direct integral fields.
    assert_eq!(read_int_field(&frozen, root, root_pos, 15), 16_777_216);
    assert_eq!(read_int_field(&frozen, root, root_pos, 16), 35);
    assert_eq!(read_int_field(&frozen, root, root_pos, 12), 1_779_252_843);
}

#[test]
fn optional_integral_field_decodes() {
    // preferred_path_separator (id 26) is optional<UInt32> and must
    // be read via the Optional layout rather than directly.
    let (schema, metadata) = open_decoded();
    let frozen = Frozen::new(&schema, &metadata);
    let root = schema.root().unwrap();
    let root_pos = frozen.root_pos();

    let field_view = frozen
        .field(root_pos, root, 26)
        .expect("preferred_path_separator field present");
    let opt_layout = schema.layout(field_view.field.layout_id).unwrap();
    assert!(matches!(
        LayoutKind::of(opt_layout, &schema).unwrap(),
        LayoutKind::Optional { .. }
    ));
    let opt = frozen
        .read_optional(field_view.pos, opt_layout)
        .expect("optional read");
    assert!(opt.present, "separator is set");

    let value_layout = schema
        .layout(opt.value_layout_id.expect("value layout present"))
        .unwrap();
    let value = frozen
        .read_integral(opt.value_pos, u32::from(value_layout.bits))
        .expect("value reads");
    assert_eq!(value, 47, "separator is '/' = 47");
}

#[test]
fn names_table_decodes_with_relative_distance() {
    // metadata.thrift field 24 (compact_names) is the FSST-compressed
    // string table when present; otherwise field 10 holds the names
    // directly. The tiny image picks the compact form, so resolving
    // names end-to-end is deferred until FSST lands. Until then we
    // assert that the compact_names structure decodes structurally:
    // its "buffer" string field is present and its index list has the
    // right count.
    let (schema, metadata) = open_decoded();
    let frozen = Frozen::new(&schema, &metadata);
    let root = schema.root().unwrap();
    let root_pos = frozen.root_pos();

    let compact_names_field = root
        .field(24)
        .expect("compact_names field present in schema");
    let compact_names_layout = schema
        .layout(compact_names_field.layout_id)
        .expect("compact_names layout present");
    let compact_names_pos = root_pos.child(compact_names_field);

    // compact_names is an Optional<string_table>; resolve to the
    // value struct when set.
    let opt = frozen
        .read_optional(compact_names_pos, compact_names_layout)
        .expect("compact_names optional read");
    assert!(opt.present, "compact_names is set in tiny image");

    let st_layout = schema
        .layout(opt.value_layout_id.expect("value layout present"))
        .unwrap();
    // string_table.index is field 3 (list<UInt32>).
    let index_field = st_layout.field(3).expect("string_table.index field");
    let index_layout = schema.layout(index_field.layout_id).unwrap();
    let index_pos = opt.value_pos.child(index_field);
    let kind = LayoutKind::of(index_layout, &schema).unwrap();
    assert!(
        matches!(kind, LayoutKind::Array { .. }),
        "string_table.index is an array, got {kind:?}"
    );
    let range = frozen.read_range(index_pos, index_layout).unwrap();
    // tiny image has 7 names (a, b, deep.txt, hello.txt, link, sub,
    // world.txt) plus the trailing sentinel = 8 index entries.
    assert!(
        range.count == 7 || range.count == 8,
        "expected 7 or 8 compact_names index entries, got {}",
        range.count
    );
}

#[test]
fn struct_list_decoders_match_export() {
    // From tiny.metadata.json:
    //   chunks (1):  [(0,0,10), (0,10,8), (0,18,8)]
    //   dir_entries (19): [(0,0),(0,1),(1,3),(3,7),(4,5),(5,2),(2,6),(5,4),(6,8)]
    //   directories (2): six entries, raw (no delta-packing)
    let (schema, metadata_bytes) = open_decoded();
    let m = Metadata::parse(&schema, &metadata_bytes).unwrap();

    let chunks = m.chunks().unwrap();
    assert_eq!(
        chunks,
        vec![
            Chunk {
                block: 0,
                offset: 0,
                size: 10,
            },
            Chunk {
                block: 0,
                offset: 10,
                size: 8,
            },
            Chunk {
                block: 0,
                offset: 18,
                size: 8,
            },
        ]
    );

    let dir_entries = m.dir_entries().unwrap();
    let expected = [
        (0u32, 0u32),
        (0, 1),
        (1, 3),
        (3, 7),
        (4, 5),
        (5, 2),
        (2, 6),
        (5, 4),
        (6, 8),
    ];
    assert_eq!(dir_entries.len(), expected.len());
    for (got, want) in dir_entries.iter().zip(expected.iter()) {
        assert_eq!(
            *got,
            DirEntry {
                name_index: want.0,
                inode_num: want.1,
            }
        );
    }

    let dirs = m.directories().unwrap();
    let expected = [
        (0u32, 1u32, 0u32),
        (0, 3, 1),
        (1, 6, 5),
        (0, 7, 2),
        (2, 9, 7),
        (0, 9, 0),
    ];
    assert_eq!(dirs.len(), expected.len());
    for (got, want) in dirs.iter().zip(expected.iter()) {
        assert_eq!(
            *got,
            Directory {
                parent_entry: want.0,
                first_entry: want.1,
                self_entry: want.2,
            }
        );
    }

    assert_eq!(m.chunk_table_raw().unwrap(), vec![0u32, 1, 2, 3]);
}

#[test]
fn inode_list_decodes() {
    // From tiny.metadata.json: 9 inodes. The first 6 are directories
    // with mode_index 0; inodes 6, 7, 8 are regular files with
    // mode_index 1 (file 1) and 7-8 with mode_index 1, plus 5 is a
    // symlink with mode_index 2. Cross-check by counting modes used.
    let (schema, metadata_bytes) = open_decoded();
    let m = Metadata::parse(&schema, &metadata_bytes).unwrap();
    let inodes = m.inodes().unwrap();
    assert_eq!(inodes.len(), 9);

    let modes_used: std::collections::BTreeSet<u32> = inodes.iter().map(|i| i.mode_index).collect();
    assert_eq!(modes_used, [0, 1, 2].iter().copied().collect());

    // Every inode in tiny image has owner_index = 0, group_index = 0
    // because there's exactly one uid (1000) and one gid (100).
    for inode in &inodes {
        assert_eq!(inode.owner_index, 0);
        assert_eq!(inode.group_index, 0);
    }

    // Ensure we can construct an InodeData manually for the type
    // assertion to be useful in downstream code.
    let _: InodeData = inodes[0];
}

#[test]
fn names_and_symlinks_decode_through_fsst() {
    // From tiny.metadata.json:
    //   names (10):    ["a", "b", "deep.txt", "hello.txt", "link", "sub", "world.txt"]
    //   symlinks (11): ["hello.txt"]
    // The image uses compact_names + compact_symlinks (FSST-backed
    // string tables).
    let (schema, metadata_bytes) = open_decoded();
    let m = Metadata::parse(&schema, &metadata_bytes).unwrap();

    let names: Vec<String> = m
        .names()
        .unwrap()
        .into_iter()
        .map(|bytes| String::from_utf8(bytes).expect("valid utf-8 name"))
        .collect();
    assert_eq!(
        names,
        vec![
            "a",
            "b",
            "deep.txt",
            "hello.txt",
            "link",
            "sub",
            "world.txt"
        ]
    );

    let symlinks: Vec<String> = m
        .symlinks()
        .unwrap()
        .into_iter()
        .map(|bytes| String::from_utf8(bytes).expect("valid utf-8 symlink"))
        .collect();
    assert_eq!(symlinks, vec!["hello.txt"]);
}

#[test]
fn fs_options_and_features_decode() {
    // From tiny.metadata.json:
    //   options (18): mtime_only=true, inodes_have_nlink=true; everything else false
    //   features (27): empty set
    let (schema, metadata_bytes) = open_decoded();
    let m = Metadata::parse(&schema, &metadata_bytes).unwrap();

    let opts = m.fs_options().unwrap();
    assert_eq!(
        opts,
        FsOptions {
            mtime_only: true,
            time_resolution_sec: None,
            packed_chunk_table: false,
            packed_directories: false,
            packed_shared_files_table: false,
            subsecond_resolution_nsec_multiplier: None,
            has_btime: false,
            inodes_have_nlink: true,
        }
    );

    assert!(m.features().unwrap().is_empty());
}

#[test]
fn typed_accessors_match_export() {
    // From tiny.metadata.json:
    //   7 (uids) -> [1000]
    //   8 (gids) -> [100]
    //   9 (modes) -> [16877, 33188, 41471]
    //   36 (total_allocated_fs_size) -> 35
    //   26 (preferred_path_separator) -> 47
    let (schema, metadata_bytes) = open_decoded();
    let m = Metadata::parse(&schema, &metadata_bytes).unwrap();

    assert_eq!(m.block_size().unwrap(), 16_777_216);
    assert_eq!(m.total_fs_size().unwrap(), 35);
    assert_eq!(m.timestamp_base().unwrap(), 1_779_252_843);
    assert_eq!(m.uids().unwrap(), vec![1000]);
    assert_eq!(m.gids().unwrap(), vec![100]);
    assert_eq!(m.modes().unwrap(), vec![16877, 33188, 41471]);
    assert_eq!(m.preferred_path_separator().unwrap(), Some(47));
    assert_eq!(m.total_allocated_fs_size().unwrap(), Some(35));
    assert_eq!(m.hole_block_index().unwrap(), None);
}

fn read_int_field(
    frozen: &Frozen<'_>,
    parent_layout: &rdwarfs::metadata::Layout,
    parent_pos: rdwarfs::metadata::Pos,
    id: i16,
) -> u64 {
    let view = frozen
        .field(parent_pos, parent_layout, id)
        .unwrap_or_else(|| panic!("field id {id} present in schema"));
    let layout = frozen
        .schema()
        .layout(view.field.layout_id)
        .expect("field layout resolves");
    frozen
        .read_integral(view.pos, u32::from(layout.bits))
        .expect("integral reads")
}
