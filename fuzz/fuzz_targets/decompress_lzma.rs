//! Fuzz the LZMA decoder. Capped output size keeps the test bounded.

#![no_main]

use libfuzzer_sys::fuzz_target;

const CAP: usize = 1 << 20;

fuzz_target!(|data: &[u8]| {
    let _ = rdwarfs::compression::decompress(rdwarfs::format::Compression::Lzma, data, CAP);
});
