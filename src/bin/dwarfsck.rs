//! `dwarfsck` CLI: inspect and verify a DwarFS image.
//!
//! Mirrors the upstream `dwarfsck` flag surface (DwarFS 0.14.0). Every
//! upstream flag is accepted: honored flags drive real behavior;
//! flags whose full semantics need infrastructure that has not landed
//! yet print a one-line stderr note and continue.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{ArgAction, Parser};

use rdwarfs::format::{FileSource, HEADER_LEN, Image, ImageSource};
use rdwarfs::fs::Filesystem;

#[derive(Parser)]
#[command(
    name = "dwarfsck",
    about = "Inspect and verify a DwarFS image",
    disable_help_flag = true,
    disable_version_flag = true
)]
struct Cli {
    /// Input filesystem image.
    #[arg(short = 'i', long = "input")]
    input: PathBuf,

    /// Detail level (0-7, or comma-separated feature list). Currently
    /// the integer form is honored: 0 = silent, 1 = summary,
    /// 2 = sections, 3+ = sections plus metadata summary.
    #[arg(short = 'd', long = "detail", default_value = "1")]
    detail: String,

    /// Suppress all output unless an error occurs.
    #[arg(short = 'q', long = "quiet", action = ArgAction::SetTrue)]
    quiet: bool,

    /// Produce verbose output (raises detail by one level).
    #[arg(short = 'v', long = "verbose", action = ArgAction::SetTrue)]
    verbose: bool,

    /// Byte offset of the image inside the input file. `auto` scans
    /// for the first section header; a number seeks straight to it.
    #[arg(short = 'O', long = "image-offset", default_value = "auto")]
    image_offset: String,

    /// Byte length of the image inside the input file. Bytes past it
    /// are never read, which is what allows an image followed by
    /// unrelated data to be opened.
    #[arg(long = "image-size")]
    image_size: Option<u64>,

    /// Print the filesystem header (script-prefix bytes) to stdout
    /// and exit.
    #[arg(short = 'H', long = "print-header", action = ArgAction::SetTrue)]
    print_header: bool,

    /// List every file in the filesystem and exit.
    #[arg(short = 'l', long = "list", action = ArgAction::SetTrue)]
    list: bool,

    /// Print per-file checksums using the named algorithm. Accepted
    /// for parity; not yet implemented.
    #[arg(long = "checksum")]
    checksum: Option<String>,

    /// Number of reader worker threads. Accepted for parity; the
    /// current reader is single-threaded.
    #[arg(short = 'n', long = "num-workers", default_value = "16")]
    num_workers: u32,

    /// Block cache size. Accepted for parity; the current reader uses
    /// a tiny built-in cache.
    #[arg(short = 's', long = "cache-size", default_value = "512m")]
    cache_size: String,

    /// Verify each block's SHA-512/256 hash in addition to the fast
    /// XXH3-64 check.
    #[arg(long = "check-integrity", action = ArgAction::SetTrue)]
    check_integrity: bool,

    /// Skip block checksum verification entirely.
    #[arg(long = "no-check", action = ArgAction::SetTrue)]
    no_check: bool,

    /// Emit information as JSON. Accepted for parity; not yet
    /// implemented.
    #[arg(short = 'j', long = "json", action = ArgAction::SetTrue)]
    json: bool,

    /// Export the raw Frozen2 metadata to a JSON file. Accepted for
    /// parity; not yet implemented (use upstream `dwarfsck` for now).
    #[arg(long = "export-metadata")]
    export_metadata: Option<PathBuf>,

    /// Log level. Accepted for parity; messages go to stderr
    /// unconditionally.
    #[arg(long = "log-level", default_value = "info")]
    log_level: String,

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
            eprintln!("dwarfsck: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let _ = (
        cli.log_level.as_str(),
        cli.cache_size.as_str(),
        cli.num_workers,
    );

    let image = open_image(&cli.input, &cli.image_offset, cli.image_size)?;

    if cli.print_header {
        let base = image.base_offset() as usize;
        if base > 0 {
            io::stdout().write_all(&image.read_range(0, base as u64)?)?;
        }
        return Ok(());
    }

    if !cli.no_check {
        if cli.check_integrity {
            image.verify_deep()?;
        } else {
            image.verify_all()?;
        }
    }

    if cli.json {
        let fs = Filesystem::open(image)?;
        print_json(&fs)?;
        return Ok(());
    }

    if let Some(out_path) = cli.export_metadata.as_deref() {
        let fs = Filesystem::open(image)?;
        export_metadata(&fs, out_path)?;
        return Ok(());
    }

    if let Some(alg) = cli.checksum.as_deref() {
        let fs = Filesystem::open(image)?;
        print_checksums(&fs, alg)?;
        return Ok(());
    }

    if cli.list {
        let fs = Filesystem::open(image)?;
        let entries = fs.walk()?;
        let stdout = io::stdout();
        let mut out = stdout.lock();
        for entry in &entries {
            if entry.path.is_empty() {
                continue;
            }
            // Upstream `dwarfsck --list` emits root-relative paths
            // without a leading slash.
            let trimmed = entry.path.strip_prefix(b"/").unwrap_or(&entry.path);
            out.write_all(trimmed)?;
            out.write_all(b"\n")?;
        }
        return Ok(());
    }

    let mut detail = parse_detail(&cli.detail)?;
    if cli.quiet {
        detail = 0;
    }
    if cli.verbose {
        detail = detail.saturating_add(1);
    }
    if detail == 0 {
        return Ok(());
    }

    print_summary(&image, detail)?;
    print_history(&image)?;

    // Everything below comes from the metadata. A corrupt or truncated
    // image still gets the section summary above.
    match Filesystem::open(image) {
        Ok(fs) => print_metadata_summary(&fs, detail)?,
        Err(err) => warn(&format!("metadata unavailable: {err}")),
    }
    Ok(())
}

fn parse_detail(value: &str) -> Result<u32, String> {
    if let Ok(n) = value.parse::<u32>() {
        return Ok(n.min(7));
    }
    // Feature lists are accepted but mapped to detail level 3 for
    // now; named features are not individually honored yet.
    Ok(3)
}

fn print_summary(image: &Image, detail: u32) -> io::Result<()> {
    use rdwarfs::format::SectionType;
    let stdout = io::stdout();
    let mut out = stdout.lock();

    // Aggregate per-section-type sizes so we can mirror upstream's
    // "block size", "metadata size" summary lines. Both compressed
    // (payload as written) and uncompressed (what the decoder would
    // produce) counts are useful when comparing codec choices.
    let mut block_count: usize = 0;
    let mut block_compressed: u64 = 0;
    let mut metadata_compressed: u64 = 0;
    let mut schema_compressed: u64 = 0;
    let mut history_compressed: u64 = 0;
    let mut unknown: Vec<(u16, u64)> = Vec::new();
    for record in image.sections() {
        let len = record.header.payload_len;
        match record.header.section_type {
            SectionType::Block => {
                block_count += 1;
                block_compressed += len;
            }
            SectionType::MetadataV2 => metadata_compressed += len,
            SectionType::MetadataV2Schema => schema_compressed += len,
            SectionType::History => history_compressed += len,
            SectionType::Unknown(value) => match unknown.iter_mut().find(|(v, _)| *v == value) {
                Some((_, total)) => *total += len,
                None => unknown.push((value, len)),
            },
            SectionType::SectionIndex => {}
        }
    }

    if let Some(first) = image.sections().first() {
        writeln!(
            out,
            "DwarFS version: {}.{}",
            first.header.major, first.header.minor
        )?;
    }
    writeln!(out, "DwarFS image: {} bytes", image.len())?;
    writeln!(out, "Sections: {}", image.sections().len())?;
    writeln!(out, "Block count: {block_count}")?;
    writeln!(out, "Compressed block size: {block_compressed} bytes")?;
    writeln!(out, "Compressed metadata size: {metadata_compressed} bytes")?;
    if let Some(n) = decoded_len(image, SectionType::MetadataV2) {
        writeln!(out, "Uncompressed metadata size: {n} bytes")?;
    }
    writeln!(out, "Compressed schema size: {schema_compressed} bytes")?;
    if let Some(n) = decoded_len(image, SectionType::MetadataV2Schema) {
        writeln!(out, "Uncompressed schema size: {n} bytes")?;
    }
    if history_compressed > 0 {
        writeln!(out, "Compressed history size: {history_compressed} bytes")?;
    }
    for (value, len) in &unknown {
        writeln!(out, "Unknown section type {value}: {len} bytes")?;
    }
    if image.base_offset() > 0 {
        writeln!(out, "Header prefix: {} bytes", image.base_offset())?;
    }
    if detail >= 2 {
        for (i, record) in image.sections().iter().enumerate() {
            let payload_end =
                record.file_offset as usize + HEADER_LEN + record.header.payload_len as usize;
            writeln!(
                out,
                "  [{i}] type={:?} compression={:?} number={} offset={} len={} end={}",
                record.header.section_type,
                record.header.compression,
                record.header.number,
                record.file_offset,
                HEADER_LEN as u64 + record.header.payload_len,
                payload_end,
            )?;
        }
    }
    if image.section_index().is_some() {
        writeln!(out, "Section index: present")?;
    }
    Ok(())
}

/// Root metadata field ids and the names `metadata.thrift` gives them.
///
/// Only tables whose elements are fixed-width are listed. A table of
/// strings costs its range headers plus the bytes of every string, and
/// the schema alone does not say how long those are, so reporting one
/// from the schema would undercount it.
const METADATA_TABLES: &[(i16, &str)] = &[
    (1, "chunks"),
    (2, "directories"),
    (3, "inodes"),
    (4, "chunk_table"),
    (6, "symlink_table"),
    (7, "uids"),
    (8, "gids"),
    (9, "modes"),
    (17, "devices"),
    (19, "dir_entries"),
    (20, "shared_files_table"),
    (29, "block_categories"),
    (35, "large_hole_size"),
];

/// Report how much of the metadata each table occupies.
///
/// Sizes are derived from the schema: an array's element count times
/// the bits the schema assigns one element. Tables holding no entries
/// are omitted, since a table that costs nothing is not interesting.
fn print_table_sizes(image: &Image) -> io::Result<()> {
    use rdwarfs::format::SectionType;
    use rdwarfs::metadata::{LayoutKind, Metadata, Pos, Schema};

    let (Some(schema_rec), Some(meta_rec)) = (
        image.find_section(SectionType::MetadataV2Schema),
        image.find_section(SectionType::MetadataV2),
    ) else {
        return Ok(());
    };
    let (Ok(schema_bytes), Ok(meta_bytes)) = (
        image.decompress_section(schema_rec, 1 << 24),
        image.decompress_section(meta_rec, 1 << 30),
    ) else {
        return Ok(());
    };
    let (Ok(schema),) = (Schema::parse(&schema_bytes),) else {
        return Ok(());
    };
    let Ok(meta) = Metadata::parse(&schema, &meta_bytes) else {
        return Ok(());
    };
    let Ok(root_layout) = schema.root() else {
        return Ok(());
    };

    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "Metadata tables:")?;
    for (id, name) in METADATA_TABLES {
        let Some(field) = root_layout.field(*id) else {
            continue;
        };
        let Ok(layout) = schema.layout(field.layout_id) else {
            continue;
        };
        // An optional wrapper has to be unwrapped before the array
        // underneath it can be measured.
        let pos = Pos::root().child(field);
        let (layout, pos) = match LayoutKind::of(layout, &schema) {
            Ok(LayoutKind::Optional { value_layout_id }) => {
                let Ok(opt) = meta.frozen().read_optional(pos, layout) else {
                    continue;
                };
                match (
                    opt.present,
                    value_layout_id.and_then(|v| schema.layout(v).ok()),
                ) {
                    (true, Some(inner)) => (inner, opt.value_pos),
                    _ => continue,
                }
            }
            _ => (layout, pos),
        };
        let Ok(LayoutKind::Array { item_layout_id }) = LayoutKind::of(layout, &schema) else {
            continue;
        };
        let (Ok(range), Ok(item)) = (
            meta.frozen().read_range(pos, layout),
            schema.layout(item_layout_id),
        ) else {
            continue;
        };
        if range.count == 0 {
            continue;
        }
        let bits = range.count * u64::from(item.bits.max(1));
        writeln!(
            out,
            "  {name:<20} {:>10} entries {:>10} bytes",
            range.count,
            bits.div_ceil(8)
        )?;
    }
    Ok(())
}

/// Decoded size of the first section of a type, when it decodes.
fn decoded_len(image: &Image, kind: rdwarfs::format::SectionType) -> Option<usize> {
    let record = image.find_section(kind)?;
    image
        .decompress_section(record, 1 << 30)
        .ok()
        .map(|b| b.len())
}

/// Note something on stderr without failing the run.
fn warn(message: &str) {
    let _ = writeln!(io::stderr(), "dwarfsck: {message}");
}

/// Report the `HISTORY` sections an image carries, if any.
fn print_history(image: &Image) -> io::Result<()> {
    use rdwarfs::format::{SectionType, history};
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for record in image
        .sections()
        .iter()
        .filter(|s| s.header.section_type == SectionType::History)
    {
        let Ok(payload) = image.decompress_section(record, 1 << 24) else {
            warn("history section could not be decoded");
            continue;
        };
        let Ok(entries) = history::parse(&payload) else {
            warn("history section could not be parsed");
            continue;
        };
        for entry in entries {
            let v = &entry.version;
            writeln!(
                out,
                "History: {}.{}.{} on {} built with {}",
                v.major, v.minor, v.patch, entry.system_id, entry.compiler_id
            )?;
            if let Some(ts) = entry.timestamp {
                writeln!(out, "  created on: {ts}")?;
            }
            if let Some(args) = entry.arguments.as_ref() {
                writeln!(out, "  args: {}", args.join(" "))?;
            }
        }
    }
    Ok(())
}

fn print_metadata_summary(fs: &Filesystem, detail: u32) -> io::Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "Block size: {} bytes", fs.block_size())?;
    let categories = fs.category_names();
    if !categories.is_empty() {
        writeln!(out, "Block categories: {}", categories.join(", "))?;
    }
    writeln!(out, "Inode count: {}", fs.inode_count())?;
    writeln!(
        out,
        "Original filesystem size: {} bytes",
        fs.total_fs_size()
    )?;
    if let Some(allocated) = fs.total_allocated_fs_size() {
        writeln!(out, "Original allocated size: {allocated} bytes")?;
    }
    if !fs.features().is_empty() {
        writeln!(out, "Features: {}", fs.features().join(", "))?;
    }
    let options = fs.options();
    let mut flags: Vec<&str> = Vec::new();
    if options.mtime_only {
        flags.push("mtime_only");
    }
    if options.packed_chunk_table {
        flags.push("packed_chunk_table");
    }
    if options.packed_directories {
        flags.push("packed_directories");
    }
    if options.packed_shared_files_table {
        flags.push("packed_shared_files_table");
    }
    if options.has_btime {
        flags.push("has_btime");
    }
    if options.inodes_have_nlink {
        flags.push("inodes_have_nlink");
    }
    if !flags.is_empty() {
        writeln!(out, "Options: {}", flags.join(", "))?;
    }
    writeln!(
        out,
        "Time resolution: {} seconds",
        options.time_resolution_sec.unwrap_or(1)
    )?;
    if let Some(sep) = fs.preferred_path_separator()
        && let Some(c) = char::from_u32(sep)
    {
        writeln!(out, "Preferred path separator: {c}")?;
    }
    if detail < 3 {
        return Ok(());
    }
    drop(out);
    print_table_sizes(fs.image())?;
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let offsets = fs.offsets();
    writeln!(
        out,
        "Inode offsets: dir={} symlink={} file={} shared={} device={} special={}",
        offsets.dir_offset,
        offsets.symlink_offset,
        offsets.file_offset,
        offsets.shared_file_offset,
        offsets.device_offset,
        offsets.special_offset,
    )?;
    Ok(())
}

/// Print one line per regular file: `<hex digest>  <path>`. The
/// algorithm string matches upstream's GNU coreutils-style aliases:
/// `sha256`, `sha512`, `xxh3-64`, `xxh3-128`. Anything else returns
/// a usage error.
fn print_checksums(fs: &Filesystem, alg: &str) -> Result<(), Box<dyn std::error::Error>> {
    use rdwarfs::fs::{BlockCache, InodeKind};
    use sha2::{Digest, Sha256, Sha512};
    use xxhash_rust::xxh3::{xxh3_64, xxh3_128};
    let entries = fs.walk()?;
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let cache = BlockCache::new(8 * fs.block_size() as usize);
    for entry in entries {
        if entry.kind != InodeKind::Regular || entry.path.is_empty() {
            continue;
        }
        let size = fs.file_size(entry.inode)?;
        // Streaming digest so multi-GB files don't blow up memory.
        let mut sha256 = Sha256::new();
        let mut sha512 = Sha512::new();
        let mut buf64 = Vec::with_capacity(size as usize);
        let mut buf128 = Vec::with_capacity(size as usize);
        let mut offset = 0u64;
        while offset < size {
            let chunk = fs.read_at(entry.inode, offset, 64 * 1024, &cache)?;
            match alg {
                "sha256" => sha256.update(&chunk),
                "sha512" => sha512.update(&chunk),
                // The xxh3 crate has no streaming API; collect bytes
                // and hash in one shot at end of file. For huge
                // inputs callers should prefer a sha digest.
                "xxh3-64" => buf64.extend_from_slice(&chunk),
                "xxh3-128" => buf128.extend_from_slice(&chunk),
                _ => return Err(format!("unknown --checksum algorithm `{alg}`").into()),
            }
            if chunk.is_empty() {
                break;
            }
            offset += chunk.len() as u64;
        }
        let digest_hex = match alg {
            "sha256" => hex_encode(sha256.finalize().as_slice()),
            "sha512" => hex_encode(sha512.finalize().as_slice()),
            "xxh3-64" => format!("{:016x}", xxh3_64(&buf64)),
            "xxh3-128" => format!("{:032x}", xxh3_128(&buf128)),
            _ => unreachable!(),
        };
        let path = entry.path.strip_prefix(b"/").unwrap_or(&entry.path);
        out.write_all(digest_hex.as_bytes())?;
        out.write_all(b"  ")?;
        out.write_all(path)?;
        out.write_all(b"\n")?;
    }
    Ok(())
}

/// Dump the parsed filesystem metadata to `out_path` (or stdout for
/// `-`) as one JSON object per inode. Suitable for piping into `jq`
/// / external diffing tools. The schema is intentionally narrow:
/// each line is one inode record with kind, mode, owner, times,
/// size, and (for symlinks) target.
fn export_metadata(
    fs: &Filesystem,
    out_path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use rdwarfs::fs::InodeKind;
    use std::fs::File;
    use std::io::BufWriter;

    let writer: Box<dyn std::io::Write> = if out_path == std::path::Path::new("-") {
        Box::new(BufWriter::new(io::stdout().lock()))
    } else {
        Box::new(BufWriter::new(File::create(out_path)?))
    };
    let mut w = writer;
    let entries = fs.walk()?;
    for entry in entries {
        let stat = fs.stat(entry.inode)?;
        let kind = match stat.kind {
            InodeKind::Directory => "directory",
            InodeKind::Regular => "regular",
            InodeKind::Symlink => "symlink",
            InodeKind::BlockDevice => "block-device",
            InodeKind::CharDevice => "char-device",
            InodeKind::Fifo => "fifo",
            InodeKind::Socket => "socket",
            _ => "unknown",
        };
        let path = if entry.path.is_empty() {
            "/".to_string()
        } else {
            String::from_utf8_lossy(&entry.path).into_owned()
        };
        write!(
            w,
            "{{\"inode\":{},\"path\":{},\"kind\":\"{}\",\"mode\":{},\"uid\":{},\"gid\":{},\"mtime\":{},\"atime\":{},\"ctime\":{},\"size\":{},\"nlink\":{}",
            stat.inode,
            json_string(&path),
            kind,
            stat.mode,
            stat.uid,
            stat.gid,
            stat.mtime,
            stat.atime,
            stat.ctime,
            stat.size,
            stat.nlink,
        )?;
        if stat.kind == InodeKind::Symlink
            && let Ok(target) = fs.read_link(stat.inode)
        {
            write!(
                w,
                ",\"target\":{}",
                json_string(&String::from_utf8_lossy(target))
            )?;
        }
        writeln!(w, "}}")?;
    }
    Ok(())
}

/// JSON-quote a string. Escapes the minimum needed (backslash,
/// double-quote, control bytes) so the output stays one line per
/// inode and parseable by any JSON consumer.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Emit a one-line JSON object summarizing the image. The fields
/// mirror the subset of upstream `dwarfsck --json` we can populate
/// today; future fields (history, compressed/uncompressed sizes) can
/// land without breaking consumers because we keep the schema strict
/// (no trailing comma, double-quoted keys).
fn print_json(fs: &Filesystem) -> io::Result<()> {
    let opts = fs.options();
    let mut options: Vec<&str> = Vec::new();
    if opts.packed_chunk_table {
        options.push("packed_chunk_table");
    }
    if opts.packed_directories {
        options.push("packed_directories");
    }
    if opts.packed_shared_files_table {
        options.push("packed_shared_files_table");
    }
    if opts.inodes_have_nlink {
        options.push("inodes_have_nlink");
    }
    if opts.has_btime {
        options.push("has_btime");
    }
    if opts.mtime_only {
        options.push("mtime_only");
    }
    let offsets = fs.offsets();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    write!(out, "{{")?;
    write!(out, "\"block_size\":{},", fs.block_size())?;
    write!(out, "\"inode_count\":{},", fs.inode_count())?;
    write!(out, "\"total_fs_size\":{},", fs.total_fs_size())?;
    if let Some(allocated) = fs.total_allocated_fs_size() {
        write!(out, "\"total_allocated_fs_size\":{allocated},")?;
    }
    write!(
        out,
        "\"time_resolution_sec\":{},",
        opts.time_resolution_sec.unwrap_or(1)
    )?;
    write!(
        out,
        "\"features\":[{}],",
        fs.features()
            .iter()
            .map(|f| json_string(f))
            .collect::<Vec<_>>()
            .join(",")
    )?;
    write!(
        out,
        "\"categories\":[{}],",
        fs.category_names()
            .iter()
            .map(|c| json_string(c))
            .collect::<Vec<_>>()
            .join(",")
    )?;
    if let Some(sep) = fs.preferred_path_separator() {
        write!(out, "\"preferred_path_separator\":{sep},")?;
    }
    write!(out, "\"dir_offset\":{},", offsets.dir_offset)?;
    write!(out, "\"symlink_offset\":{},", offsets.symlink_offset)?;
    write!(out, "\"file_offset\":{},", offsets.file_offset)?;
    write!(
        out,
        "\"shared_file_offset\":{},",
        offsets.shared_file_offset
    )?;
    write!(out, "\"device_offset\":{},", offsets.device_offset)?;
    write!(out, "\"special_offset\":{},", offsets.special_offset)?;
    write!(out, "\"timestamp_base\":{},", fs.timestamp_base())?;
    write!(out, "\"options\":[")?;
    for (i, opt) in options.iter().enumerate() {
        if i > 0 {
            write!(out, ",")?;
        }
        write!(out, "\"{opt}\"")?;
    }
    write!(out, "]")?;
    writeln!(out, "}}")?;
    Ok(())
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
