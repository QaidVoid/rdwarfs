//! `dwarfs` CLI: mount a DwarFS image read-only via FUSE.
//!
//! Behavior tracks the upstream `dwarfs` flag surface. The binary is
//! a thin shell over the `rdwarfs` library and requires the `fuse`
//! Cargo feature.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{ArgAction, Parser};

use rdwarfs::format::Image;
use rdwarfs::fs::Filesystem;
use rdwarfs::fuse::DwarfsFuse;

#[derive(Parser)]
#[command(
    name = "dwarfs",
    about = "Mount a DwarFS image read-only via FUSE",
    disable_help_flag = true,
    disable_version_flag = true
)]
struct Cli {
    /// Path to the DwarFS image to mount.
    image: PathBuf,

    /// Mount point (must be an existing empty directory).
    mountpoint: PathBuf,

    /// Run in the foreground (do not daemonize). Accepted for
    /// parity; our mount is always foreground today.
    #[arg(short = 'f', long = "foreground", action = ArgAction::SetTrue)]
    foreground: bool,

    /// Allow other users to access the mount. Maps to FUSE's
    /// `allow_other`.
    #[arg(long = "allow-other", action = ArgAction::SetTrue)]
    allow_other: bool,

    /// Mount option (`-o key=value`), accepted multiple times and
    /// comma-separated. `cachesize=SIZE` sets the decoded-block cache
    /// budget; anything else is passed through to FUSE.
    #[arg(short = 'o', long = "option")]
    options: Vec<String>,

    /// Show help and exit.
    #[arg(short = 'h', long = "help", action = ArgAction::Help)]
    help: Option<bool>,
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    let cli = match Cli::try_parse_from(&args) {
        Ok(c) => c,
        Err(err) => {
            let _ = err.print();
            return ExitCode::from(2);
        }
    };
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("dwarfs: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let _ = cli.foreground;

    // Sections are verified lazily as they are loaded, so a mount does
    // not pay for hashing block data it may never read.
    let (cache_bytes, passthrough) = split_options(&cli.options)?;

    let image = Image::open(&cli.image)?;
    let fs = Filesystem::open(image)?;
    let adapter = match cache_bytes {
        Some(bytes) => DwarfsFuse::with_cache(fs, bytes),
        None => DwarfsFuse::new(fs),
    };

    let mut mount_options: Vec<fuser::MountOption> = vec![
        fuser::MountOption::FSName("dwarfs".to_string()),
        fuser::MountOption::Subtype("rdwarfs".to_string()),
        fuser::MountOption::RO,
        // DwarFS images are immutable; surfacing them as noatime/
        // nosuid/nodev matches what upstream `dwarfs` advertises and
        // keeps the kernel from issuing writes we can't accept.
        fuser::MountOption::NoAtime,
        fuser::MountOption::NoSuid,
        fuser::MountOption::NoDev,
    ];
    for raw in passthrough {
        mount_options.push(fuser::MountOption::CUSTOM(raw));
    }
    let mut config = fuser::Config::default();
    config.mount_options = mount_options;
    if cli.allow_other {
        config.acl = fuser::SessionACL::All;
    }

    fuser::mount2(adapter, &cli.mountpoint, &config)?;
    Ok(())
}

/// Pull `cachesize` out of the `-o` list, returning it and the options
/// that belong to FUSE. Values may be comma-separated within one `-o`.
fn split_options(
    options: &[String],
) -> Result<(Option<usize>, Vec<String>), Box<dyn std::error::Error>> {
    let mut cache = None;
    let mut rest = Vec::new();
    for raw in options {
        for opt in raw.split(',') {
            match opt.strip_prefix("cachesize=") {
                Some(value) => cache = Some(parse_size(value)?),
                None if opt.is_empty() => {}
                None => rest.push(opt.to_string()),
            }
        }
    }
    Ok((cache, rest))
}

/// Parse a byte size with an optional binary suffix, as upstream
/// `dwarfs` accepts for `cachesize` (for example `512M`).
fn parse_size(value: &str) -> Result<usize, String> {
    let trimmed = value.trim();
    let digits = trimmed.trim_end_matches(|c: char| c.is_ascii_alphabetic());
    let suffix = trimmed[digits.len()..].to_ascii_lowercase();
    let scale: usize = match suffix.trim_end_matches('b') {
        "" => 1,
        "k" => 1 << 10,
        "m" => 1 << 20,
        "g" => 1 << 30,
        "t" => 1u64
            .checked_shl(40)
            .map(|v| v as usize)
            .unwrap_or(usize::MAX),
        other => return Err(format!("unknown size suffix `{other}` in `{value}`")),
    };
    let number: usize = digits
        .parse()
        .map_err(|_| format!("`{value}` is not a byte size"))?;
    number
        .checked_mul(scale)
        .ok_or_else(|| format!("`{value}` overflows a byte size"))
}

#[cfg(test)]
mod tests {
    use super::{parse_size, split_options};

    #[test]
    fn sizes_accept_binary_suffixes() {
        assert_eq!(parse_size("512"), Ok(512));
        assert_eq!(parse_size("512M"), Ok(512 << 20));
        assert_eq!(parse_size("512MB"), Ok(512 << 20));
        assert_eq!(parse_size("1g"), Ok(1 << 30));
        assert_eq!(parse_size(" 64K "), Ok(64 << 10));
        assert!(parse_size("512X").is_err());
        assert!(parse_size("").is_err());
    }

    #[test]
    fn cachesize_is_split_from_the_fuse_options() {
        let opts = vec![
            "cachesize=256M,allow_root".to_string(),
            "kernel_cache".to_string(),
        ];
        let (cache, rest) = split_options(&opts).expect("parse");
        assert_eq!(cache, Some(256 << 20));
        assert_eq!(
            rest,
            vec!["allow_root".to_string(), "kernel_cache".to_string()]
        );
    }

    #[test]
    fn absent_cachesize_leaves_the_default() {
        let (cache, rest) = split_options(&["ro".to_string()]).expect("parse");
        assert_eq!(cache, None);
        assert_eq!(rest, vec!["ro".to_string()]);
    }
}
