//! Fuzz both opening and integrity verification of an image. Covers
//! the section iterator, hash checks, and section-index parsing.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(image) = rdwarfs::format::Image::from_vec(data.to_vec()) {
        let _ = image.verify_all();
    }
});
