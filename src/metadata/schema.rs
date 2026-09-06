//! Frozen2 schema parser.
//!
//! The METADATA_V2_SCHEMA section is a Thrift compact-encoded
//! [`Schema`] struct. It records, for each Thrift type touched by the
//! metadata, a [`Layout`] describing how its fields map into the
//! bit-packed metadata blob: bit widths for primitives, bit or byte
//! offsets for struct fields, and a small set of well-known fields
//! (`distance`, `count`, `isset`) for ranges, strings, and optionals.
//!
//! Schema source: `frozen/thrift/lib/thrift/frozen.thrift` (Apache).

use std::collections::BTreeMap;

use crate::Error;
use crate::metadata::thrift::{TType, ThriftReader};

/// One field of a Frozen2 layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    /// Index into [`Schema::layouts`] giving the field value's layout.
    pub layout_id: i16,
    /// Field placement:
    ///   - `offset < 0`: bit offset within the parent struct, equal to
    ///     `-offset`.
    ///   - `offset >= 0`: byte offset within the parent.
    pub offset: i16,
}

impl Field {
    /// Bit offset of this field, derived from [`Field::offset`].
    pub fn bit_offset(&self) -> u64 {
        if self.offset < 0 {
            -(self.offset as i32) as u64
        } else {
            (self.offset as u64) * 8
        }
    }

    /// Byte offset of this field, derived from [`Field::offset`].
    pub fn byte_offset(&self) -> u64 {
        if self.offset < 0 {
            (-(self.offset as i32) as u64) / 8
        } else {
            self.offset as u64
        }
    }

    /// True when the field is anchored at a bit offset rather than a
    /// whole-byte offset.
    pub fn is_bit_offset(&self) -> bool {
        self.offset < 0
    }
}

/// One layout in the schema.
#[derive(Debug, Clone, Default)]
pub struct Layout {
    /// Total byte size of the value when stored inline. Zero when the
    /// layout is not inline-sized (typical for variable-length ranges
    /// referenced via distance).
    pub size: u32,
    /// Bit width for integral layouts. Zero for non-integrals.
    pub bits: u16,
    /// Fields by thrift field id.
    pub fields: BTreeMap<i16, Field>,
    /// Type name as recorded by the writer (diagnostic only).
    pub type_name: String,
}

impl Layout {
    /// Look up a field by thrift id.
    pub fn field(&self, id: i16) -> Option<&Field> {
        self.fields.get(&id)
    }

    /// True when this layout describes an integral value (no fields,
    /// non-zero bit width).
    pub fn is_integral(&self) -> bool {
        self.bits > 0 && self.fields.is_empty()
    }
}

/// Parsed Frozen2 schema.
#[derive(Debug, Clone)]
pub struct Schema {
    /// Frozen2 file format version. Frozen2 is version 1.
    pub file_version: i32,
    /// Whether the writer disabled strict type-name matching.
    pub relax_type_checks: bool,
    /// Layouts keyed by id.
    pub layouts: BTreeMap<i16, Layout>,
    /// Id of the root layout.
    pub root_layout: i16,
}

impl Schema {
    /// Parse a Thrift compact-encoded schema blob.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = ThriftReader::new(bytes);
        r.read_struct_begin();
        let mut schema = Schema {
            file_version: 0,
            relax_type_checks: false,
            layouts: BTreeMap::new(),
            root_layout: 0,
        };

        while let Some(field) = r.read_field_header()? {
            match (field.id, field.ttype) {
                (1, TType::BoolTrue) => schema.relax_type_checks = true,
                (1, TType::BoolFalse) => schema.relax_type_checks = false,
                (2, TType::Map) => schema.layouts = read_layout_map(&mut r)?,
                (3, TType::I16) => schema.root_layout = r.read_i16()?,
                (4, TType::I32) => schema.file_version = r.read_i32()?,
                (_, ttype) => r.skip_value(ttype)?,
            }
        }
        r.read_struct_end();

        Ok(schema)
    }

    /// Borrow the root layout.
    pub fn root(&self) -> Result<&Layout, Error> {
        self.layouts
            .get(&self.root_layout)
            .ok_or_else(|| Error::Decode {
                codec: "frozen2-schema",
                message: format!("root layout id {} not present", self.root_layout),
            })
    }

    /// Borrow a layout by id.
    pub fn layout(&self, id: i16) -> Result<&Layout, Error> {
        self.layouts.get(&id).ok_or_else(|| Error::Decode {
            codec: "frozen2-schema",
            message: format!("layout id {id} not present"),
        })
    }
}

fn read_layout_map(r: &mut ThriftReader<'_>) -> Result<BTreeMap<i16, Layout>, Error> {
    let (kt, vt, count) = r.read_map_header()?;
    if count > 0 && (kt != TType::I16 || vt != TType::Struct) {
        return Err(Error::Decode {
            codec: "frozen2-schema",
            message: format!("layout map has unexpected key/value types {kt:?}/{vt:?}"),
        });
    }
    let mut out = BTreeMap::new();
    for _ in 0..count {
        let key = r.read_i16()?;
        let layout = read_layout(r)?;
        out.insert(key, layout);
    }
    Ok(out)
}

fn read_layout(r: &mut ThriftReader<'_>) -> Result<Layout, Error> {
    r.read_struct_begin();
    let mut layout = Layout::default();
    while let Some(field) = r.read_field_header()? {
        match (field.id, field.ttype) {
            (1, TType::I32) => {
                let v = r.read_i32()?;
                layout.size = u32::try_from(v).map_err(|_| Error::Decode {
                    codec: "frozen2-schema",
                    message: format!("layout size {v} is negative"),
                })?;
            }
            (2, TType::I16) => {
                let v = r.read_i16()?;
                layout.bits = u16::try_from(v).map_err(|_| Error::Decode {
                    codec: "frozen2-schema",
                    message: format!("layout bits {v} is negative"),
                })?;
            }
            (3, TType::Map) => layout.fields = read_field_map(r)?,
            (4, TType::Binary) => layout.type_name = r.read_string()?.to_string(),
            (_, ttype) => r.skip_value(ttype)?,
        }
    }
    r.read_struct_end();
    Ok(layout)
}

fn read_field_map(r: &mut ThriftReader<'_>) -> Result<BTreeMap<i16, Field>, Error> {
    let (kt, vt, count) = r.read_map_header()?;
    if count > 0 && (kt != TType::I16 || vt != TType::Struct) {
        return Err(Error::Decode {
            codec: "frozen2-schema",
            message: format!("field map has unexpected key/value types {kt:?}/{vt:?}"),
        });
    }
    let mut out = BTreeMap::new();
    for _ in 0..count {
        let key = r.read_i16()?;
        let field = read_field(r)?;
        out.insert(key, field);
    }
    Ok(out)
}

fn read_field(r: &mut ThriftReader<'_>) -> Result<Field, Error> {
    r.read_struct_begin();
    let mut field = Field {
        layout_id: 0,
        offset: 0,
    };
    while let Some(fh) = r.read_field_header()? {
        match (fh.id, fh.ttype) {
            (1, TType::I16) => field.layout_id = r.read_i16()?,
            (2, TType::I16) => field.offset = r.read_i16()?,
            (_, ttype) => r.skip_value(ttype)?,
        }
    }
    r.read_struct_end();
    Ok(field)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_varint(value: u64, out: &mut Vec<u8>) {
        let mut v = value;
        loop {
            let mut byte = (v & 0x7F) as u8;
            v >>= 7;
            if v != 0 {
                byte |= 0x80;
                out.push(byte);
            } else {
                out.push(byte);
                return;
            }
        }
    }

    fn write_zigzag(value: i64, out: &mut Vec<u8>) {
        let zz = ((value << 1) ^ (value >> 63)) as u64;
        write_varint(zz, out);
    }

    fn write_field_header(prev: &mut i16, ttype: u8, id: i16, out: &mut Vec<u8>) {
        let delta = (id - *prev) as i32;
        if (1..=15).contains(&delta) {
            out.push(((delta as u8) << 4) | ttype);
        } else {
            out.push(ttype);
            write_zigzag(id as i64, out);
        }
        *prev = id;
    }

    fn write_string_field(prev: &mut i16, id: i16, value: &str, out: &mut Vec<u8>) {
        write_field_header(prev, 8, id, out);
        write_varint(value.len() as u64, out);
        out.extend(value.as_bytes());
    }

    fn write_i16_field(prev: &mut i16, id: i16, value: i16, out: &mut Vec<u8>) {
        write_field_header(prev, 4, id, out);
        write_zigzag(value as i64, out);
    }

    fn write_i32_field(prev: &mut i16, id: i16, value: i32, out: &mut Vec<u8>) {
        write_field_header(prev, 5, id, out);
        write_zigzag(value as i64, out);
    }

    fn build_field(layout_id: i16, offset: i16) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut prev = 0i16;
        write_i16_field(&mut prev, 1, layout_id, &mut buf);
        write_i16_field(&mut prev, 2, offset, &mut buf);
        buf.push(0); // STOP
        buf
    }

    fn build_layout(size: u32, bits: u16, fields: &[(i16, Vec<u8>)], type_name: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut prev = 0i16;
        if size != 0 {
            write_i32_field(&mut prev, 1, size as i32, &mut buf);
        }
        if bits != 0 {
            write_i16_field(&mut prev, 2, bits as i16, &mut buf);
        }
        if !fields.is_empty() {
            write_field_header(&mut prev, 11, 3, &mut buf); // type Map
            write_varint(fields.len() as u64, &mut buf);
            // i16 (4) keys, struct (12) values
            buf.push((4 << 4) | 12);
            for (k, body) in fields {
                write_zigzag(*k as i64, &mut buf);
                buf.extend(body);
            }
        }
        write_string_field(&mut prev, 4, type_name, &mut buf);
        buf.push(0);
        buf
    }

    fn build_schema(
        file_version: i32,
        root: i16,
        layouts: &[(i16, Vec<u8>)],
        relax: bool,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut prev = 0i16;
        if relax {
            write_field_header(&mut prev, 1, 1, &mut buf);
        }
        // map layouts as field 2
        write_field_header(&mut prev, 11, 2, &mut buf);
        write_varint(layouts.len() as u64, &mut buf);
        buf.push((4 << 4) | 12);
        for (k, body) in layouts {
            write_zigzag(*k as i64, &mut buf);
            buf.extend(body);
        }
        write_i16_field(&mut prev, 3, root, &mut buf);
        write_i32_field(&mut prev, 4, file_version, &mut buf);
        buf.push(0);
        buf
    }

    #[test]
    fn parses_minimal_schema() {
        // Layout 1: a struct with one field referring to layout 2
        let f = build_field(2, -3);
        let layout1 = build_layout(4, 0, &[(7, f)], "struct demo");
        // Layout 2: an integer with 5 bits
        let layout2 = build_layout(0, 5, &[], "i32");
        let blob = build_schema(1, 1, &[(1, layout1), (2, layout2)], true);

        let schema = Schema::parse(&blob).unwrap();
        assert_eq!(schema.file_version, 1);
        assert_eq!(schema.root_layout, 1);
        assert!(schema.relax_type_checks);

        let root = schema.root().unwrap();
        assert_eq!(root.size, 4);
        assert_eq!(root.type_name, "struct demo");
        let f = root.field(7).unwrap();
        assert_eq!(f.layout_id, 2);
        assert!(f.is_bit_offset());
        assert_eq!(f.bit_offset(), 3);

        let int = schema.layout(2).unwrap();
        assert!(int.is_integral());
        assert_eq!(int.bits, 5);
    }

    #[test]
    fn missing_root_layout_errors() {
        let layout1 = build_layout(0, 0, &[], "phantom");
        let blob = build_schema(1, 99, &[(1, layout1)], false);
        let schema = Schema::parse(&blob).unwrap();
        assert!(schema.root().is_err());
    }

    #[test]
    fn field_offset_byte_path() {
        let f = Field {
            layout_id: 0,
            offset: 7,
        };
        assert!(!f.is_bit_offset());
        assert_eq!(f.byte_offset(), 7);
        assert_eq!(f.bit_offset(), 56);
    }
}
