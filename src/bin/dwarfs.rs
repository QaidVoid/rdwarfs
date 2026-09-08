//! `dwarfs` CLI: mount a DwarFS image read-only via FUSE.
//!
//! Behavior tracks the upstream `dwarfs` flag surface. The binary is
//! a thin shell over the `rdwarfs` library and requires the `fuse`
//! Cargo feature.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{ArgAction, Parser};

use rdwarfs::format::{FileSource, Image, ImageSource};
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
    /// budget, `offset=NUM|auto` locates an image embedded in a larger
    /// file; anything else is passed through to FUSE.
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
    let (cache_bytes, offset, passthrough) = split_options(&cli.options)?;

    let image = open_image(&cli.image, offset)?;
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

/// Where an image begins inside the file holding it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Offset {
    /// The file is the image.
    Start,
    /// Scan for the first section header.
    Detect,
    /// Seek straight to this byte offset.
    At(u64),
}

type SplitOptions = (Option<usize>, Offset, Vec<String>);

/// Pull `cachesize` and `offset` out of the `-o` list, returning them
/// and the options that belong to FUSE. Values may be comma-separated
/// within one `-o`.
fn split_options(options: &[String]) -> Result<SplitOptions, Box<dyn std::error::Error>> {
    let mut cache = None;
    let mut offset = Offset::Start;
    let mut rest = Vec::new();
    for raw in options {
        for opt in raw.split(',') {
            if let Some(value) = opt.strip_prefix("cachesize=") {
                cache = Some(parse_size(value)?);
            } else if let Some(value) = opt.strip_prefix("offset=") {
                offset =
                    match value {
                        "auto" => Offset::Detect,
                        other => Offset::At(other.parse::<u64>().map_err(|_| {
                            format!("offset must be `auto` or a byte offset: {other}")
                        })?),
                    };
            } else if !opt.is_empty() {
                rest.push(opt.to_string());
            }
        }
    }
    Ok((cache, offset, rest))
}

/// Open the image, honouring an embedded offset.
///
/// Reads positionally rather than mapping the file. A mount is
/// long-lived, and mapping it charges every faulted-in page of the
/// compressed image to the daemon's RSS: on a 434 MB image that is
/// another 262 MB resident, for no gain in read speed.
fn open_image(path: &PathBuf, offset: Offset) -> Result<Image, Box<dyn std::error::Error>> {
    let source = FileSource::open(path)?;
    match offset {
        // `from_source` scans for the first section header itself, so
        // detection and the plain case share a path.
        Offset::Start | Offset::Detect => Ok(Image::from_source(source)?),
        Offset::At(at) => {
            let len = ImageSource::len(&source).saturating_sub(at);
            Ok(Image::from_window(source, at, len)?)
        }
    }
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
    use super::{Offset, parse_size, split_options};

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
        let (cache, offset, rest) = split_options(&opts).expect("parse");
        assert_eq!(cache, Some(256 << 20));
        assert_eq!(offset, Offset::Start);
        assert_eq!(
            rest,
            vec!["allow_root".to_string(), "kernel_cache".to_string()]
        );
    }

    #[test]
    fn absent_options_leave_the_defaults() {
        let (cache, offset, rest) = split_options(&["ro".to_string()]).expect("parse");
        assert_eq!(cache, None);
        assert_eq!(offset, Offset::Start);
        assert_eq!(rest, vec!["ro".to_string()]);
    }

    #[test]
    fn offset_accepts_auto_and_a_number() {
        let (_, offset, rest) = split_options(&["offset=auto".to_string()]).expect("parse");
        assert_eq!(offset, Offset::Detect);
        assert!(rest.is_empty(), "offset is consumed, not passed to FUSE");

        let (_, offset, _) = split_options(&["offset=123456".to_string()]).expect("parse");
        assert_eq!(offset, Offset::At(123_456));

        assert!(split_options(&["offset=nope".to_string()]).is_err());
    }
}
