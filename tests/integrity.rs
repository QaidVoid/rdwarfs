//! When section hashes are checked.

#![cfg(feature = "read")]

mod harness;

use harness::{VECTORS, vector_bytes};
use rdwarfs::format::Image;

#[test]
fn every_fixture_verifies() {
    for name in VECTORS {
        let image = Image::from_vec(vector_bytes(name)).expect("parse");
        image
            .verify_all()
            .unwrap_or_else(|e| panic!("fixture {name} failed verification: {e}"));
    }
}

/// Flip a byte well inside the first section's payload, past the
/// 64-byte header, so the header still parses and only the hash and
/// the payload disagree.
fn corrupt_payload(name: &str) -> Vec<u8> {
    let mut bytes = vector_bytes(name);
    let at = 64 + 8;
    bytes[at] ^= 0xFF;
    bytes
}

#[test]
fn a_corrupt_payload_is_rejected_by_verification() {
    let image = Image::from_vec(corrupt_payload("upstream-default")).expect("still parses");
    assert!(
        image.verify_all().is_err(),
        "a flipped payload byte must fail verification"
    );
}

#[test]
fn a_corrupt_payload_is_caught_when_the_section_is_decoded() {
    // Verification is lazy: opening an image does not hash every
    // section, so a reader that never touches a section never pays for
    // it. Decoding one must still check.
    let bytes = corrupt_payload("upstream-default");
    let opened = Image::from_vec(bytes).expect("parse");
    let corrupt_section = *opened.sections().first().expect("at least one section");
    assert!(
        opened
            .decompress_section(&corrupt_section, 1 << 24)
            .is_err(),
        "decoding a corrupt section must fail rather than return bad bytes"
    );
}

#[test]
fn truncation_is_reported_rather_than_panicking() {
    let full = vector_bytes("upstream-default");
    for cut in [1usize, 32, 63, 64, 65, full.len() / 2, full.len() - 1] {
        let _ = Image::from_vec(full[..cut].to_vec());
    }
}

#[test]
fn a_flipped_byte_anywhere_never_panics() {
    let full = vector_bytes("upstream-default");
    let step = (full.len() / 64).max(1);
    let mut at = 0;
    while at < full.len() {
        let mut bytes = full.clone();
        bytes[at] ^= 0x01;
        if let Ok(image) = Image::from_vec(bytes) {
            let _ = image.verify_all();
        }
        at += step;
    }
}
