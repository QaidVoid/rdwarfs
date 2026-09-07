//! Fuzz the top-level container parser: a hostile attacker feeds us
//! arbitrary bytes; `Image::from_vec` must reject malformed input
//! without panicking, aborting, or allocating unboundedly.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rdwarfs::format::Image::from_vec(data.to_vec());
});
