//! `HISTORY` section decoder.
//!
//! The section is Thrift compact encoded per `thrift/history.thrift`.
//! It is purely informational: an image reads correctly whether or not
//! it carries one, and unknown fields are skipped so a section written
//! by a newer producer still decodes as far as it can.

use crate::Error;
use crate::metadata::thrift::{TType, ThriftReader};

/// Version of the implementation that wrote a history entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistoryVersion {
    /// Major version number.
    pub major: u16,
    /// Minor version number.
    pub minor: u16,
    /// Patch version number.
    pub patch: u16,
    /// Whether the writer identified itself as a tagged release.
    pub is_release: bool,
    /// Source revision, when the writer recorded one.
    pub git_rev: Option<String>,
    /// Source branch, when the writer recorded one.
    pub git_branch: Option<String>,
    /// Source description, when the writer recorded one.
    pub git_desc: Option<String>,
}

/// One recorded build of an image.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistoryEntry {
    /// Version of the writer.
    pub version: HistoryVersion,
    /// Host identifier the writer ran on.
    pub system_id: String,
    /// Compiler that built the writer.
    pub compiler_id: String,
    /// Command line, when the writer recorded one.
    pub arguments: Option<Vec<String>>,
    /// Build time in epoch seconds, when the writer recorded one.
    pub timestamp: Option<u64>,
    /// Versions of libraries the writer linked against.
    pub library_versions: Vec<String>,
}

/// Decode a `HISTORY` section payload into its entries.
pub fn parse(payload: &[u8]) -> Result<Vec<HistoryEntry>, Error> {
    let mut r = ThriftReader::new(payload);
    let mut entries = Vec::new();
    r.read_struct_begin();
    while let Some(field) = r.read_field_header()? {
        match (field.id, field.ttype) {
            (1, TType::List) => {
                let (element, count) = r.read_list_header()?;
                if element != TType::Struct {
                    return Err(decode("history entries are not structs"));
                }
                for _ in 0..count {
                    entries.push(read_entry(&mut r)?);
                }
            }
            (_, ttype) => r.skip_value(ttype)?,
        }
    }
    r.read_struct_end();
    Ok(entries)
}

fn read_entry(r: &mut ThriftReader<'_>) -> Result<HistoryEntry, Error> {
    let mut entry = HistoryEntry::default();
    r.read_struct_begin();
    while let Some(field) = r.read_field_header()? {
        match (field.id, field.ttype) {
            (1, TType::Struct) => entry.version = read_version(r)?,
            (2, TType::Binary) => entry.system_id = read_utf8(r)?,
            (3, TType::Binary) => entry.compiler_id = read_utf8(r)?,
            (4, TType::List) => entry.arguments = Some(read_string_list(r)?),
            (5, TType::I64) => entry.timestamp = Some(r.read_i64()?.max(0) as u64),
            (6, TType::Set) => {
                let (element, count) = r.read_set_header()?;
                if element != TType::Binary {
                    return Err(decode("library_versions is not a set of strings"));
                }
                for _ in 0..count {
                    entry.library_versions.push(read_utf8(r)?);
                }
            }
            (_, ttype) => r.skip_value(ttype)?,
        }
    }
    r.read_struct_end();
    Ok(entry)
}

fn read_version(r: &mut ThriftReader<'_>) -> Result<HistoryVersion, Error> {
    let mut version = HistoryVersion::default();
    r.read_struct_begin();
    while let Some(field) = r.read_field_header()? {
        match (field.id, field.ttype) {
            (1, TType::I16) => version.major = r.read_i16()?.max(0) as u16,
            (2, TType::I16) => version.minor = r.read_i16()?.max(0) as u16,
            (3, TType::I16) => version.patch = r.read_i16()?.max(0) as u16,
            (4, TType::BoolTrue) => version.is_release = true,
            (4, TType::BoolFalse) => version.is_release = false,
            (5, TType::Binary) => version.git_rev = Some(read_utf8(r)?),
            (6, TType::Binary) => version.git_branch = Some(read_utf8(r)?),
            (7, TType::Binary) => version.git_desc = Some(read_utf8(r)?),
            (_, ttype) => r.skip_value(ttype)?,
        }
    }
    r.read_struct_end();
    Ok(version)
}

fn read_string_list(r: &mut ThriftReader<'_>) -> Result<Vec<String>, Error> {
    let (element, count) = r.read_list_header()?;
    if element != TType::Binary {
        return Err(decode("expected a list of strings"));
    }
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        out.push(read_utf8(r)?);
    }
    Ok(out)
}

/// Read a string field. History strings are human-readable text, so a
/// non-UTF-8 value is reported rather than silently replaced.
fn read_utf8(r: &mut ThriftReader<'_>) -> Result<String, Error> {
    Ok(r.read_string()?.to_string())
}

fn decode(message: &str) -> Error {
    Error::Decode {
        codec: "history",
        message: message.to_string(),
    }
}
