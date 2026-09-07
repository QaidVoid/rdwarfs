//! End-to-end FUSE mount test.
//!
//! Spawns the `dwarfs` binary against a committed image, walks the
//! mountpoint to confirm directory listings, file contents, and
//! symlink targets line up with what the source tree contained. The
//! test runs only when FUSE is usable on the host; without a
//! `fusermount` helper on `PATH` or an accessible `/dev/fuse` we skip
//! quietly so CI on container images without FUSE still passes.

#![cfg(all(unix, feature = "fuse"))]

mod harness;

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// Path to one of this crate's binaries.
///
/// Cargo exports `CARGO_BIN_EXE_<name>` to integration tests. Deriving
/// the path from `current_exe()` instead breaks whenever cargo changes
/// its target-directory layout.
fn rdwarfs_bin(name: &str) -> PathBuf {
    PathBuf::from(match name {
        "dwarfs" => env!("CARGO_BIN_EXE_dwarfs"),
        other => panic!("no such binary target: {other}"),
    })
}

/// Name of the unprivileged FUSE unmount helper available on this host.
///
/// FUSE 3 installs `fusermount3`; FUSE 2 installs `fusermount`. A host
/// may carry either or both.
fn fusermount_helper() -> Option<&'static str> {
    ["fusermount3", "fusermount"].into_iter().find(|helper| {
        Command::new(helper)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

fn fuse_available() -> bool {
    Path::new("/dev/fuse").exists() && fusermount_helper().is_some()
}

fn wait_for_mount(mountpoint: &Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(entries) = std::fs::read_dir(mountpoint) {
            if entries.flatten().next().is_some() {
                return;
            }
        }
        if let Ok(Some(_)) = child.try_wait() {
            panic!("dwarfs mount exited before mountpoint populated");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("mountpoint never populated within 5s");
}

#[test]
fn dwarfs_mount_walks_source_tree() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount unavailable");
        return;
    }
    let mountpoint = std::env::temp_dir().join("rdwarfs-fuse-mnt");
    let image = std::env::temp_dir().join("rdwarfs-fuse.dwarfs");
    let _ = std::fs::remove_dir_all(&mountpoint);
    std::fs::write(&image, harness::vector_bytes("upstream-default")).unwrap();
    std::fs::create_dir_all(&mountpoint).unwrap();

    let dwarfs = rdwarfs_bin("dwarfs");
    let mut child = Command::new(&dwarfs)
        .args([image.to_str().unwrap(), mountpoint.to_str().unwrap()])
        .spawn()
        .expect("spawn dwarfs");

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wait_for_mount(&mountpoint, &mut child);

        let top = std::fs::read(mountpoint.join("top.txt")).unwrap();
        assert_eq!(top, b"top level\n");
        let deep = std::fs::read(mountpoint.join("dir/nested/deep.txt")).unwrap();
        assert_eq!(deep, b"nested\n");
        let target = std::fs::read_link(mountpoint.join("dir/link-to-top")).unwrap();
        assert_eq!(target.to_string_lossy(), "../top.txt");
        let mut names: Vec<String> = std::fs::read_dir(&mountpoint)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert!(names.contains(&"top.txt".to_string()), "listing: {names:?}");
        assert!(names.contains(&"dir".to_string()), "listing: {names:?}");
    }));

    if let Some(helper) = fusermount_helper() {
        let _ = Command::new(helper)
            .args(["-u", mountpoint.to_str().unwrap()])
            .status();
    }
    let _ = child.wait();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}
