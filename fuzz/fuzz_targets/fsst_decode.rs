//! Fuzz the FSST symbol-table parser plus a decode pass. We split
//! the input into a symbol-table blob and a payload using a single
//! length prefix the fuzzer can drive.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let split = data[0] as usize;
    if split > data.len() {
        return;
    }
    let (table_bytes, payload) = data[1..].split_at(split.min(data.len() - 1));
    if let Ok((table, _)) = rdwarfs::metadata::SymTable::parse(table_bytes) {
        let _ = table.decode_to_vec(payload);
    }
});
