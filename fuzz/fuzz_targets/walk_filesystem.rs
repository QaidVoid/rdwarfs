//! Open a fuzzer-provided image and walk every inode end-to-end:
//! list directories, stat each entry, read regular-file payloads,
//! and resolve symlinks. Catches mismatches between the schema, the
//! Frozen2 reader, and the high-level filesystem API.

#![no_main]

use libfuzzer_sys::fuzz_target;

use rdwarfs::format::Image;
use rdwarfs::fs::{BlockCache, Filesystem, InodeKind};

fuzz_target!(|data: &[u8]| {
    let Ok(image) = Image::from_vec(data.to_vec()) else {
        return;
    };
    if image.verify_all().is_err() {
        return;
    }
    let Ok(fs) = Filesystem::open(image) else {
        return;
    };
    let Ok(entries) = fs.walk() else {
        return;
    };
    let mut cache = BlockCache::new(2);
    for entry in entries.iter().take(1024) {
        let _ = fs.stat(entry.inode);
        match entry.kind {
            InodeKind::Regular => {
                let _ = fs.read_at(entry.inode, 0, 4096, &mut cache);
            }
            InodeKind::Symlink => {
                let _ = fs.read_link(entry.inode);
            }
            _ => {}
        }
    }
});
