//! Thrift compact-protocol decoder.
//!
//! Implements the subset of the spec required to read DwarFS sections
//! encoded with Thrift compact protocol: the Frozen2 schema, the
//! history struct, and the compression options blobs. Unknown fields
//! are skipped, every length and offset is bounds-checked, and no
//! decode path allocates more than the input justifies.
//!
//! Spec: Apache Thrift, "Compact Protocol Encoding".

#![allow(dead_code)]

use crate::Error;

/// Compact-protocol type codes (field-context and container-element
/// context).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TType {
    Stop,
    BoolTrue,
    BoolFalse,
    I8,
    I16,
    I32,
    I64,
    Double,
    Binary,
    List,
    Set,
    Map,
    Struct,
}

impl TType {
    fn from_code(code: u8) -> Result<Self, Error> {
        Ok(match code & 0x0F {
            0 => Self::Stop,
            1 => Self::BoolTrue,
            2 => Self::BoolFalse,
            3 => Self::I8,
            4 => Self::I16,
            5 => Self::I32,
            6 => Self::I64,
            7 => Self::Double,
            8 => Self::Binary,
            9 => Self::List,
            10 => Self::Set,
            11 => Self::Map,
            12 => Self::Struct,
            other => return Err(decode(format!("unknown thrift type code {other}"))),
        })
    }
}

/// A field header within a struct.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FieldHeader {
    /// Compact-protocol type code for the field's value.
    pub(crate) ttype: TType,
    /// Resolved thrift field id (delta or explicit i16).
    pub(crate) id: i16,
}

/// Compact-protocol reader over a borrowed slice.
pub(crate) struct ThriftReader<'a> {
    bytes: &'a [u8],
    pos: usize,
    /// Per-struct frame of the most recently read field id (resets on
    /// every nested struct).
    last_field_id: i16,
    stack: Vec<i16>,
}

impl<'a> ThriftReader<'a> {
    /// Wrap a byte slice in a new reader.
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pos: 0,
            last_field_id: 0,
            stack: Vec::new(),
        }
    }

    /// Number of bytes consumed so far.
    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    fn read_byte(&mut self) -> Result<u8, Error> {
        let b = *self
            .bytes
            .get(self.pos)
            .ok_or_else(|| decode("unexpected end of thrift input".to_string()))?;
        self.pos += 1;
        Ok(b)
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| decode("length overflow in thrift input".to_string()))?;
        if end > self.bytes.len() {
            return Err(decode(format!(
                "thrift slice of {len} bytes at {} runs past end",
                self.pos
            )));
        }
        let s = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    /// Read an unsigned varint (LEB128).
    pub(crate) fn read_varint_u64(&mut self) -> Result<u64, Error> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        for _ in 0..10 {
            let b = self.read_byte()?;
            let chunk = u64::from(b & 0x7F);
            result |= chunk
                .checked_shl(shift)
                .ok_or_else(|| decode("varint overflow".to_string()))?;
            if b & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
        }
        Err(decode("varint too long".to_string()))
    }

    fn read_zigzag_i64(&mut self) -> Result<i64, Error> {
        let v = self.read_varint_u64()?;
        Ok(((v >> 1) as i64) ^ -((v & 1) as i64))
    }

    /// Read a signed i16 (zigzag varint).
    pub(crate) fn read_i16(&mut self) -> Result<i16, Error> {
        let v = self.read_zigzag_i64()?;
        i16::try_from(v).map_err(|_| decode(format!("value {v} out of range for i16")))
    }

    /// Read a signed i32 (zigzag varint).
    pub(crate) fn read_i32(&mut self) -> Result<i32, Error> {
        let v = self.read_zigzag_i64()?;
        i32::try_from(v).map_err(|_| decode(format!("value {v} out of range for i32")))
    }

    /// Read a signed i64 (zigzag varint).
    pub(crate) fn read_i64(&mut self) -> Result<i64, Error> {
        self.read_zigzag_i64()
    }

    /// Read an i8 (single byte).
    pub(crate) fn read_i8(&mut self) -> Result<i8, Error> {
        Ok(self.read_byte()? as i8)
    }

    /// Read a binary blob (varint length + bytes).
    pub(crate) fn read_binary(&mut self) -> Result<&'a [u8], Error> {
        let len = self.read_varint_u64()?;
        let len = usize::try_from(len)
            .map_err(|_| decode(format!("binary length {len} does not fit in usize")))?;
        self.read_slice(len)
    }

    /// Read a UTF-8 string (binary + validate).
    pub(crate) fn read_string(&mut self) -> Result<&'a str, Error> {
        let bytes = self.read_binary()?;
        std::str::from_utf8(bytes).map_err(|_| decode("non-utf8 thrift string".to_string()))
    }

    /// Read a list header. Returns `(element_type, count)`.
    pub(crate) fn read_list_header(&mut self) -> Result<(TType, u32), Error> {
        let header = self.read_byte()?;
        let etype = TType::from_code(header)?;
        let small = (header >> 4) & 0x0F;
        let count = if small == 0x0F {
            let big = self.read_varint_u64()?;
            u32::try_from(big).map_err(|_| decode(format!("list length {big} exceeds u32")))?
        } else {
            u32::from(small)
        };
        Ok((etype, count))
    }

    /// Read a set header. Same encoding as a list.
    pub(crate) fn read_set_header(&mut self) -> Result<(TType, u32), Error> {
        self.read_list_header()
    }

    /// Read a map header. Returns `(key_type, value_type, count)`.
    /// Empty maps omit the type byte entirely.
    pub(crate) fn read_map_header(&mut self) -> Result<(TType, TType, u32), Error> {
        let count = self.read_varint_u64()?;
        let count =
            u32::try_from(count).map_err(|_| decode(format!("map length {count} exceeds u32")))?;
        if count == 0 {
            return Ok((TType::Stop, TType::Stop, 0));
        }
        let kv = self.read_byte()?;
        let key = TType::from_code(kv >> 4)?;
        let val = TType::from_code(kv & 0x0F)?;
        Ok((key, val, count))
    }

    /// Begin reading a nested struct. Pushes the current field-id
    /// frame and resets the delta counter.
    pub(crate) fn read_struct_begin(&mut self) {
        self.stack.push(self.last_field_id);
        self.last_field_id = 0;
    }

    /// Finish reading a nested struct. Pops the field-id frame so the
    /// enclosing struct continues with its previous delta counter.
    pub(crate) fn read_struct_end(&mut self) {
        self.last_field_id = self.stack.pop().unwrap_or(0);
    }

    /// Read the next field header in the current struct, or `None`
    /// when STOP is reached.
    pub(crate) fn read_field_header(&mut self) -> Result<Option<FieldHeader>, Error> {
        let byte = self.read_byte()?;
        if byte == 0 {
            return Ok(None);
        }
        let ttype = TType::from_code(byte & 0x0F)?;
        let delta = (byte >> 4) & 0x0F;
        let id = if delta == 0 {
            self.read_i16()?
        } else {
            self.last_field_id
                .checked_add(i16::from(delta))
                .ok_or_else(|| decode("field id delta overflow".to_string()))?
        };
        self.last_field_id = id;
        Ok(Some(FieldHeader { ttype, id }))
    }

    /// Skip a value of the given type. Used to ignore unknown fields
    /// without reinterpreting them.
    pub(crate) fn skip_value(&mut self, ttype: TType) -> Result<(), Error> {
        match ttype {
            TType::Stop => Ok(()),
            TType::BoolTrue | TType::BoolFalse => Ok(()),
            TType::I8 => {
                self.read_byte()?;
                Ok(())
            }
            TType::I16 | TType::I32 | TType::I64 => {
                self.read_varint_u64()?;
                Ok(())
            }
            TType::Double => {
                self.read_slice(8)?;
                Ok(())
            }
            TType::Binary => {
                self.read_binary()?;
                Ok(())
            }
            TType::List | TType::Set => {
                let (etype, count) = self.read_list_header()?;
                for _ in 0..count {
                    self.skip_element(etype)?;
                }
                Ok(())
            }
            TType::Map => {
                let (kt, vt, count) = self.read_map_header()?;
                for _ in 0..count {
                    self.skip_element(kt)?;
                    self.skip_element(vt)?;
                }
                Ok(())
            }
            TType::Struct => {
                self.read_struct_begin();
                while let Some(field) = self.read_field_header()? {
                    self.skip_value(field.ttype)?;
                }
                self.read_struct_end();
                Ok(())
            }
        }
    }

    /// Skip a single container element. Container booleans take one
    /// byte (unlike struct booleans which carry the value in the type
    /// code).
    fn skip_element(&mut self, ttype: TType) -> Result<(), Error> {
        match ttype {
            TType::BoolTrue | TType::BoolFalse => {
                self.read_byte()?;
                Ok(())
            }
            other => self.skip_value(other),
        }
    }

    /// Read a single boolean element from a container.
    pub(crate) fn read_bool_element(&mut self) -> Result<bool, Error> {
        Ok(self.read_byte()? != 0)
    }
}

fn decode(message: String) -> Error {
    Error::Decode {
        codec: "thrift",
        message,
    }
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

    #[test]
    fn varint_roundtrip() {
        for v in [0u64, 1, 127, 128, 16384, u64::MAX] {
            let mut buf = Vec::new();
            write_varint(v, &mut buf);
            let mut r = ThriftReader::new(&buf);
            assert_eq!(r.read_varint_u64().unwrap(), v);
        }
    }

    #[test]
    fn zigzag_roundtrip() {
        for v in [0i64, 1, -1, 12345, -12345, i64::MAX, i64::MIN] {
            let mut buf = Vec::new();
            write_zigzag(v, &mut buf);
            let mut r = ThriftReader::new(&buf);
            assert_eq!(r.read_i64().unwrap(), v);
        }
    }

    #[test]
    fn truncated_varint_errors() {
        let mut r = ThriftReader::new(&[0x80]);
        assert!(r.read_varint_u64().is_err());
    }

    #[test]
    fn small_field_header_delta() {
        // delta = 1, ttype = I32; field id resolves to 1.
        let bytes = [(1u8 << 4) | 5, 0];
        let mut r = ThriftReader::new(&bytes);
        r.read_struct_begin();
        let f = r.read_field_header().unwrap().unwrap();
        assert_eq!(f.id, 1);
        assert_eq!(f.ttype, TType::I32);
    }

    #[test]
    fn explicit_field_id_via_delta_zero() {
        let mut buf = vec![5u8]; // delta=0, ttype=I32
        write_zigzag(42, &mut buf); // explicit i16 = 42
        buf.push(0); // STOP
        let mut r = ThriftReader::new(&buf);
        r.read_struct_begin();
        let f = r.read_field_header().unwrap().unwrap();
        assert_eq!(f.id, 42);
        assert_eq!(f.ttype, TType::I32);
        assert!(r.read_field_header().unwrap().is_none());
    }

    #[test]
    fn list_short_and_long_header() {
        // size 3, etype I32: header = 0x35
        let mut r = ThriftReader::new(&[0x35]);
        assert_eq!(r.read_list_header().unwrap(), (TType::I32, 3));

        // size 20, etype I32: header = 0xF5, varint(20)
        let mut buf = vec![0xF5u8];
        write_varint(20, &mut buf);
        let mut r = ThriftReader::new(&buf);
        assert_eq!(r.read_list_header().unwrap(), (TType::I32, 20));
    }

    #[test]
    fn map_empty_omits_type_byte() {
        let mut buf = Vec::new();
        write_varint(0, &mut buf);
        let mut r = ThriftReader::new(&buf);
        assert_eq!(r.read_map_header().unwrap(), (TType::Stop, TType::Stop, 0));
    }

    #[test]
    fn binary_and_string_roundtrip() {
        let s = "hello world";
        let mut buf = Vec::new();
        write_varint(s.len() as u64, &mut buf);
        buf.extend(s.as_bytes());
        let mut r = ThriftReader::new(&buf);
        assert_eq!(r.read_string().unwrap(), s);
    }

    #[test]
    fn skip_value_skips_struct() {
        // Outer struct with one struct field (id=1) and stop.
        // Inner struct has one I32 field id=1, value=42, stop.
        let mut inner = vec![(1u8 << 4) | 5];
        write_zigzag(42, &mut inner);
        inner.push(0);

        let mut outer = vec![(1u8 << 4) | 12];
        outer.extend(&inner);
        outer.push(0);

        let mut r = ThriftReader::new(&outer);
        r.read_struct_begin();
        let f = r.read_field_header().unwrap().unwrap();
        assert_eq!(f.ttype, TType::Struct);
        r.skip_value(TType::Struct).unwrap();
        assert!(r.read_field_header().unwrap().is_none());
        r.read_struct_end();
    }
}
