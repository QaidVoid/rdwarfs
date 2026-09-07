//! Fuzz the zstd decoder via the capped wrapper. A malicious frame
//! must not over-allocate, panic, or read past EOF.

#![no_main]

use libfuzzer_sys::fuzz_target;

const CAP: usize = 1 << 20;

fuzz_target!(|data: &[u8]| {
    let _ = rdwarfs::compression::decompress(rdwarfs::format::Compression::Zstd, data, CAP);
});
