//! Decoding the HISTORY section.
//!
//! The section is informational: an image reads correctly with or
//! without one, and a section written by a newer producer must still
//! decode as far as it can.

#![cfg(feature = "read")]

mod harness;

use harness::{VECTORS, vector_bytes};
use rdwarfs::format::{Image, SectionType, history};

fn history_of(name: &str) -> Option<Vec<history::HistoryEntry>> {
    let image = Image::from_vec(vector_bytes(name)).expect("parse");
    let record = image
        .sections()
        .iter()
        .find(|s| s.header.section_type == SectionType::History)
        .copied()?;
    let payload = image
        .decompress_section(&record, 1 << 24)
        .expect("decode history");
    Some(history::parse(&payload).expect("parse history"))
}

#[test]
fn the_history_section_decodes_in_every_fixture_that_has_one() {
    let mut seen = 0;
    for name in VECTORS {
        if let Some(entries) = history_of(name) {
            seen += 1;
            assert!(!entries.is_empty(), "fixture {name} has an empty history");
            for entry in entries {
                assert!(
                    !entry.system_id.is_empty(),
                    "fixture {name} recorded no system id"
                );
            }
        }
    }
    assert!(seen > 0, "no fixture carried a HISTORY section");
}

#[test]
fn a_recorded_version_is_populated() {
    let entries = history_of("upstream-default").expect("default fixture has history");
    let version = &entries[0].version;
    assert!(
        version.major > 0 || version.minor > 0 || version.patch > 0,
        "version should not be all zeroes"
    );
}

#[test]
fn an_image_without_a_history_section_still_opens() {
    // Every fixture opens as a filesystem whether or not it carries
    // history, which is what makes the section optional in practice.
    for name in VECTORS {
        let image = Image::from_vec(vector_bytes(name)).expect("parse");
        rdwarfs::fs::Filesystem::open(image)
            .unwrap_or_else(|e| panic!("fixture {name} failed to open: {e}"));
    }
}

#[test]
fn trailing_garbage_in_a_history_payload_is_reported_not_panicked() {
    let mut payload = vec![0u8; 8];
    payload.extend_from_slice(&[0xFF; 32]);
    let _ = history::parse(&payload);
}

#[test]
fn an_empty_history_payload_decodes_to_no_entries() {
    let entries = history::parse(&[0x00]).expect("empty struct parses");
    assert!(entries.is_empty());
}
