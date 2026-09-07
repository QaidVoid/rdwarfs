//! Fuzz the LZ4 decoder.

#![no_main]

use libfuzzer_sys::fuzz_target;

const CAP: usize = 1 << 20;

fuzz_target!(|data: &[u8]| {
    let _ = rdwarfs::compression::decompress(rdwarfs::format::Compression::Lz4, data, CAP);
});
