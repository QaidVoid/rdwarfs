//! `dwarfsextract` CLI: extract files from a DwarFS image.
//!
//! Mirrors the upstream `dwarfsextract` flag surface (DwarFS 0.14.0).
//! Every upstream flag is accepted; honored flags drive real
//! behavior, and flags whose semantics need infrastructure that has
//! not landed yet print a one-line stderr note and continue.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{ArgAction, Parser};

use rdwarfs::format::{FileSource, Image, ImageSource};
#[cfg(feature = "tar")]
use rdwarfs::fs::write_tar;
use rdwarfs::fs::{ExtractOptions, Filesystem, extract_all};

#[derive(Parser)]
#[command(
    name = "dwarfsextract",
    about = "Extract files from a DwarFS image",
    disable_help_flag = true,
    disable_version_flag = true
)]
struct Cli {
    /// Input filesystem image.
    #[arg(short = 'i', long = "input")]
    input: PathBuf,

    /// Output directory (default: current directory).
    #[arg(short = 'o', long = "output", default_value = ".")]
    output: PathBuf,

    /// Only extract files whose path matches one of these patterns.
    /// Accepted for parity; not yet implemented.
    #[arg(long = "pattern")]
    pattern: Vec<String>,

    /// Byte offset of the image inside the input file. `auto` scans
    /// for the first section header; a number seeks straight to it.
    #[arg(short = 'O', long = "image-offset", default_value = "auto")]
    image_offset: String,

    /// Byte length of the image inside the input file. Bytes past it
    /// are never read, which is what allows an image followed by
    /// unrelated data to be opened.
    #[arg(long = "image-size")]
    image_size: Option<u64>,

    /// Output format. Only `filesystem` (the default) is honored;
    /// archive formats (tar, cpio, ...) are accepted but not yet
    /// implemented.
    #[arg(short = 'f', long = "format")]
    format: Option<String>,

    /// libarchive format filters. Accepted for parity.
    #[arg(long = "format-filters")]
    format_filters: Option<String>,

    /// libarchive format options. Accepted for parity.
    #[arg(long = "format-options")]
    format_options: Option<String>,

    /// Continue if errors are encountered.
    #[arg(long = "continue-on-error", action = ArgAction::SetTrue)]
    continue_on_error: bool,

    /// Skip image-block integrity verification.
    #[arg(long = "disable-integrity-check", action = ArgAction::SetTrue)]
    disable_integrity_check: bool,

    /// Write percentage progress to stdout. Accepted for parity.
    #[arg(long = "stdout-progress", action = ArgAction::SetTrue)]
    stdout_progress: bool,

    /// Number of worker threads. Accepted for parity (current
    /// extractor is single-threaded).
    #[arg(short = 'n', long = "num-workers", default_value = "4")]
    num_workers: u32,

    /// Block cache size. Accepted for parity.
    #[arg(short = 's', long = "cache-size", default_value = "512m")]
    cache_size: String,

    /// Enable performance monitor. Accepted for parity.
    #[arg(long = "perfmon")]
    perfmon: Option<String>,

    /// Performance monitor trace file. Accepted for parity.
    #[arg(long = "perfmon-trace")]
    perfmon_trace: Option<PathBuf>,

    /// Log level. Accepted for parity.
    #[arg(long = "log-level", default_value = "info")]
    log_level: String,

    /// Enable context logging regardless of level. Accepted for
    /// parity.
    #[arg(long = "log-with-context", action = ArgAction::SetTrue)]
    log_with_context: bool,

    /// Show the manual page. Accepted for parity; defers to `--help`.
    #[arg(long = "man", action = ArgAction::SetTrue)]
    man: bool,

    /// Show help and exit.
    #[arg(short = 'h', long = "help", action = ArgAction::Help)]
    help: Option<bool>,
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    let cli = match Cli::try_parse_from(&args) {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            return ExitCode::from(2);
        }
    };
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("dwarfsextract: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    // --format gates: filesystem (extract to dir) and tar (write a
    // USTAR archive) are honored. Other libarchive-style formats
    // (cpio, mtree, etc.) are accepted but not yet implemented.
    let format = cli.format.as_deref().unwrap_or("filesystem");
    if format != "filesystem" && format != "tar" {
        warn(&format!(
            "--format={format} is accepted but only `filesystem` and `tar` are implemented"
        ));
    }
    if cli.format_filters.is_some() {
        warn("--format-filters is accepted but not yet implemented");
    }
    if cli.format_options.is_some() {
        warn("--format-options is accepted but not yet implemented");
    }
    if cli.stdout_progress {
        warn("--stdout-progress is accepted but progress reporting is not yet implemented");
    }
    if cli.perfmon.is_some() || cli.perfmon_trace.is_some() {
        warn("--perfmon is accepted but not implemented");
    }
    if cli.man {
        warn("--man is accepted; printing --help instead");
        Cli::try_parse_from(["dwarfsextract", "--help"])
            .err()
            .map(|e| e.print());
        return Ok(());
    }
    let _ = (
        cli.cache_size.as_str(),
        cli.log_level.as_str(),
        cli.log_with_context,
    );
    // `--num-workers N` caps the rayon thread pool for this process.
    // The pool is global, so we set it once before any parallel work
    // kicks off; subsequent attempts to re-configure return an error
    // we can safely ignore.
    if cli.num_workers > 0 {
        #[cfg(feature = "parallel")]
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(cli.num_workers as usize)
            .build_global();
    }

    let image = open_image(&cli.input, &cli.image_offset, cli.image_size)?;
    if !cli.disable_integrity_check {
        image.verify_all()?;
    }
    let fs = Filesystem::open(image)?;

    if format == "tar" {
        write_tar_output(&fs, &cli.output)?;
        return Ok(());
    }

    let opts = ExtractOptions {
        continue_on_error: cli.continue_on_error,
        hardlink_shared: true,
        include_patterns: cli.pattern.clone(),
    };
    let stats = extract_all(&fs, &cli.output, opts)?;

    eprintln!(
        "dwarfsextract: wrote {} files ({} hardlinks), {} dirs, {} symlinks, skipped {}",
        stats.files, stats.hardlinks, stats.directories, stats.symlinks, stats.skipped
    );
    Ok(())
}

#[cfg(feature = "tar")]
fn write_tar_output(
    fs: &Filesystem,
    output: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::BufWriter;
    // `--output -` writes to stdout; any other path opens a fresh
    // archive file. Buffered writes so the underlying syscall count
    // matches roughly one per block, not one per tar header field.
    let writer: Box<dyn std::io::Write> =
        if output == std::path::Path::new("-") || output == std::path::Path::new(".") {
            Box::new(BufWriter::new(std::io::stdout().lock()))
        } else {
            Box::new(BufWriter::new(File::create(output)?))
        };
    write_tar(fs, writer)?;
    Ok(())
}

#[cfg(not(feature = "tar"))]
fn write_tar_output(
    _fs: &Filesystem,
    _output: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("--format=tar requires the `tar` Cargo feature".into())
}

fn warn(message: &str) {
    let _ = writeln!(io::stderr(), "dwarfsextract: {message}");
}

/// Open an image, honoring an explicit offset and length.
///
/// `offset` is `auto` to scan for the first section header, or a byte
/// position. A length confines the reader to that window so unrelated
/// trailing bytes are never interpreted.
fn open_image(
    input: &Path,
    offset: &str,
    size: Option<u64>,
) -> Result<Image, Box<dyn std::error::Error>> {
    let offset = match offset {
        "auto" => None,
        other => Some(
            other
                .parse::<u64>()
                .map_err(|_| format!("--image-offset must be `auto` or a byte offset: {other}"))?,
        ),
    };
    if offset.is_none() && size.is_none() {
        return Ok(Image::open(input)?);
    }
    let source = FileSource::open(input)?;
    let offset = offset.unwrap_or(0);
    let len = size.unwrap_or_else(|| ImageSource::len(&source).saturating_sub(offset));
    Ok(Image::from_window(source, offset, len)?)
}
