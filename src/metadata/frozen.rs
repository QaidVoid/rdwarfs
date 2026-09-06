//! Frozen2 layout-driven decoder.
//!
//! The Frozen2 format places each value in a bit-packed payload at a
//! position computed from its layout. Primitives are stored as
//! bit-extents at a given bit offset; structs nest fields at child
//! positions; ranges (lists and strings) record `(count, distance)`
//! where `distance` is **relative to the range field's own byte
//! position**, not absolute within the blob. That relativity is the
//! single most common source of bugs in independent Frozen2 readers,
//! so this module makes it the explicit contract of every range
//! traversal.
//!
//! Field-kind classification is structural: a layout with no fields
//! is integral, a layout with a 1-bit field at id 1 is treated as
//! optional (`{isset, value}`), a layout with fields `{1, 2}` is a
//! string/blittable range, fields `{1, 2, 3}` an array (the item
//! layout lives at field 3), and anything else is a user struct.
//!
//! Sources: Apache-2.0 `frozen.thrift`, `Frozen.h`,
//! `FrozenRange-inl.h`, `FrozenString-inl.h`, `FrozenOptional-inl.h`.

use crate::Error;
use crate::metadata::bitbuf::BitBuf;
use crate::metadata::schema::{Field, Layout, Schema};

/// A position in the Frozen2 blob.
///
/// Mirrors the C++ `LayoutPosition`: a byte anchor plus an accumulated
/// bit offset that may exceed 8 mid-traversal.
#[derive(Debug, Clone, Copy)]
pub struct Pos {
    /// Byte anchor.
    pub byte: u64,
    /// Bit offset from `byte`. Can exceed 7 because nested bit fields
    /// accumulate before being normalized for an integral read.
    pub bit: u64,
}

impl Pos {
    /// Position of the root structure (byte 0, bit 0).
    pub fn root() -> Self {
        Self { byte: 0, bit: 0 }
    }

    /// Absolute bit offset = `byte * 8 + bit`.
    pub fn absolute_bit(&self) -> u64 {
        self.byte.saturating_mul(8).saturating_add(self.bit)
    }

    /// Compute the position of a child field. Mirrors C++
    /// `LayoutPosition::operator()(FieldPosition)`.
    pub fn child(&self, field: &Field) -> Self {
        if field.offset < 0 {
            Self {
                byte: self.byte,
                bit: self.bit + (-i32::from(field.offset)) as u64,
            }
        } else {
            Self {
                byte: self.byte + field.offset as u64,
                bit: self.bit,
            }
        }
    }
}

/// Structural classification of a [`Layout`] kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutKind {
    /// A primitive integral value with the given bit width.
    Integral(u32),
    /// A user-defined struct keyed by Thrift field id.
    Struct,
    /// A blittable range with no per-element layout (strings, byte
    /// vectors).
    String,
    /// A range of items addressed by a separate item layout id.
    Array {
        /// Layout id of the per-element layout.
        item_layout_id: i16,
    },
    /// An optional value with an isset bit and a value layout.
    ///
    /// `value_layout_id` is `None` when the writer elided the value
    /// field because the value type carries no storage (a Frozen2
    /// optimization for things like always-empty sets). In that case
    /// the optional is decoded by reading only the isset bit, and the
    /// value is the default of its type.
    Optional {
        /// Layout id of the value when present, or `None` when the
        /// value field was elided.
        value_layout_id: Option<i16>,
    },
    /// Empty layout (no storage). Treated as "not present".
    Empty,
}

impl LayoutKind {
    /// Classify a layout by its structure. Used to pick the right
    /// reader.
    ///
    /// Frozen2 elides any sub-field whose value layout is empty. The
    /// most common consequences are:
    ///
    /// - An `Optional<T>` whose value type carries no storage drops
    ///   the value field and keeps only the 1-bit isset field.
    /// - A range whose data starts at the layout's own byte position
    ///   drops the `distance` field; an always-empty range drops both
    ///   distance and count.
    ///
    /// The classifier handles each case explicitly so callers can
    /// branch on the kind without worrying about which fields the
    /// writer chose to keep.
    pub fn of(layout: &Layout, schema: &Schema) -> Result<Self, Error> {
        if layout.fields.is_empty() {
            if layout.bits == 0 && layout.size == 0 {
                return Ok(Self::Empty);
            }
            return Ok(Self::Integral(u32::from(layout.bits)));
        }

        if let Some(f1) = layout.field(1) {
            let l1 = schema.layout(f1.layout_id)?;
            if l1.fields.is_empty() && l1.bits == 1 {
                let value_layout_id = layout.field(2).map(|f| f.layout_id);
                return Ok(Self::Optional { value_layout_id });
            }
        }

        if let Some(f3) = layout.field(3) {
            return Ok(Self::Array {
                item_layout_id: f3.layout_id,
            });
        }

        if layout.field(1).is_some() || layout.field(2).is_some() {
            return Ok(Self::String);
        }

        Ok(Self::Struct)
    }
}

/// View of a resolved range or string.
#[derive(Debug, Clone, Copy)]
pub struct RangeView {
    /// Byte offset of the first element. For an empty range this is
    /// the same as the range layout's byte anchor and the count is 0.
    pub data_byte: u64,
    /// Number of elements.
    pub count: u64,
    /// Layout id of one element, if this is an [`LayoutKind::Array`].
    pub item_layout_id: Option<i16>,
}

/// View of a resolved optional.
#[derive(Debug, Clone, Copy)]
pub struct OptionalView {
    /// Whether the optional is set.
    pub present: bool,
    /// Position of the contained value when `present` is true and the
    /// value layout was not elided.
    pub value_pos: Pos,
    /// Layout id of the contained value. `None` when the writer elided
    /// the value field for an empty value type.
    pub value_layout_id: Option<i16>,
}

/// Decoder driving lookups into a Frozen2 blob via a schema.
pub struct Frozen<'a> {
    schema: &'a Schema,
    buf: BitBuf<'a>,
}

impl<'a> Frozen<'a> {
    /// Build a decoder over `bytes` interpreted under `schema`.
    pub fn new(schema: &'a Schema, bytes: &'a [u8]) -> Self {
        Self {
            schema,
            buf: BitBuf::new(bytes),
        }
    }

    /// Borrow the schema.
    pub fn schema(&self) -> &Schema {
        self.schema
    }

    /// Borrow the underlying bit buffer.
    pub fn buf(&self) -> BitBuf<'a> {
        self.buf
    }

    /// Position of the root structure.
    pub fn root_pos(&self) -> Pos {
        Pos::root()
    }

    /// Borrow the root layout from the schema.
    pub fn root_layout(&self) -> Result<&Layout, Error> {
        self.schema.root()
    }

    /// Read an integral value of `bits` width at `pos`.
    pub fn read_integral(&self, pos: Pos, bits: u32) -> Result<u64, Error> {
        self.buf.read_u64(pos.absolute_bit(), bits)
    }

    /// Read a struct field value. Returns `None` when the field is not
    /// declared in the layout (Frozen2 omits zero-byte fields). The
    /// returned position and layout id let the caller continue
    /// resolving the field.
    pub fn field<'b>(
        &self,
        parent: Pos,
        parent_layout: &'b Layout,
        id: i16,
    ) -> Option<FieldView<'b>>
    where
        'a: 'b,
    {
        parent_layout.field(id).map(|f| FieldView {
            field: *f,
            pos: parent.child(f),
            _phantom: std::marker::PhantomData,
        })
    }

    /// Resolve a range or string from a parent struct field. Applies
    /// the relative-distance rule: `data_byte = range_pos.byte + distance`.
    ///
    /// Either of `distance` (field 1) or `count` (field 2) may be
    /// elided by the writer when its value is the default (zero); the
    /// reader treats a missing field as the corresponding default.
    pub fn read_range(&self, range_pos: Pos, range_layout: &Layout) -> Result<RangeView, Error> {
        let count = if let Some(count_field) = range_layout.field(2) {
            let count_layout = self.schema.layout(count_field.layout_id)?;
            self.buf.read_u64(
                range_pos.child(count_field).absolute_bit(),
                u32::from(count_layout.bits),
            )?
        } else {
            0
        };

        let distance = if count == 0 {
            0
        } else if let Some(dist_field) = range_layout.field(1) {
            let dist_layout = self.schema.layout(dist_field.layout_id)?;
            self.buf.read_u64(
                range_pos.child(dist_field).absolute_bit(),
                u32::from(dist_layout.bits),
            )?
        } else {
            0
        };

        let data_byte = range_pos
            .byte
            .checked_add(distance)
            .ok_or_else(|| decode("range distance overflow".to_string()))?;

        Ok(RangeView {
            data_byte,
            count,
            item_layout_id: range_layout.field(3).map(|f| f.layout_id),
        })
    }

    /// Read an optional value: `(isset, value)`. The value layout may
    /// be elided when the value type carries no storage; in that case
    /// [`OptionalView::value_layout_id`] is `None` and the caller
    /// should treat a `present` optional as carrying the default value
    /// of its type.
    pub fn read_optional(&self, opt_pos: Pos, opt_layout: &Layout) -> Result<OptionalView, Error> {
        let isset_field = opt_layout.field(1).ok_or_else(|| missing_field(1))?;
        let present = self
            .buf
            .read_bool(opt_pos.child(isset_field).absolute_bit())?;
        if let Some(value_field) = opt_layout.field(2) {
            Ok(OptionalView {
                present,
                value_pos: opt_pos.child(value_field),
                value_layout_id: Some(value_field.layout_id),
            })
        } else {
            Ok(OptionalView {
                present,
                value_pos: opt_pos,
                value_layout_id: None,
            })
        }
    }

    /// Resolve a string/binary range to its raw bytes inside the
    /// underlying buffer.
    pub fn read_string_bytes(
        &self,
        range_pos: Pos,
        range_layout: &Layout,
    ) -> Result<&'a [u8], Error> {
        let range = self.read_range(range_pos, range_layout)?;
        let start = range.data_byte as usize;
        let end = start
            .checked_add(range.count as usize)
            .ok_or_else(|| decode("string slice overflow".to_string()))?;
        let bytes = self.buf.bytes();
        if end > bytes.len() {
            return Err(decode(format!(
                "string slice {start}..{end} runs past buffer of {} bytes",
                bytes.len()
            )));
        }
        Ok(&bytes[start..end])
    }

    /// Position of the `i`th element in a resolved range. For arrays
    /// with byte-sized items the element advances by `item.size`
    /// bytes; for inline integral items it advances by `item.bits`
    /// bits.
    pub fn element_pos(&self, range: RangeView, i: u64) -> Result<Pos, Error> {
        let Some(item_id) = range.item_layout_id else {
            return Ok(Pos {
                byte: range
                    .data_byte
                    .checked_add(i)
                    .ok_or_else(|| decode("string element offset overflow".to_string()))?,
                bit: 0,
            });
        };
        let item_layout = self.schema.layout(item_id)?;
        if item_layout.size > 0 {
            let off = i
                .checked_mul(u64::from(item_layout.size))
                .ok_or_else(|| decode("array element byte offset overflow".to_string()))?;
            Ok(Pos {
                byte: range
                    .data_byte
                    .checked_add(off)
                    .ok_or_else(|| decode("array element byte offset overflow".to_string()))?,
                bit: 0,
            })
        } else {
            let bits = i
                .checked_mul(u64::from(item_layout.bits))
                .ok_or_else(|| decode("array element bit offset overflow".to_string()))?;
            // The byte anchor must stay at the array's data start.
            // A nested range resolves its `distance` against `Pos::byte`,
            // so folding whole bytes out of `bits` here would move every
            // element's string data by that amount. `Pos::bit` is allowed
            // to exceed 7 for exactly this reason.
            Ok(Pos {
                byte: range.data_byte,
                bit: bits,
            })
        }
    }
}

/// Helper handle returned by [`Frozen::field`]. Carries the field's
/// position plus the schema field info for further resolution.
pub struct FieldView<'b> {
    /// The schema's field metadata (layout id and bit/byte offset).
    pub field: Field,
    /// The field's computed position.
    pub pos: Pos,
    _phantom: std::marker::PhantomData<&'b ()>,
}

fn missing_field(id: i16) -> Error {
    Error::Decode {
        codec: "frozen2",
        message: format!("expected sub-field with id {id}"),
    }
}

fn decode(message: String) -> Error {
    Error::Decode {
        codec: "frozen2",
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn integral(bits: u16) -> Layout {
        Layout {
            size: 0,
            bits,
            fields: BTreeMap::new(),
            type_name: String::new(),
        }
    }

    fn struct_layout(size: u32, fields: Vec<(i16, Field)>) -> Layout {
        let mut map = BTreeMap::new();
        for (k, v) in fields {
            map.insert(k, v);
        }
        Layout {
            size,
            bits: 0,
            fields: map,
            type_name: String::new(),
        }
    }

    #[test]
    fn child_pos_byte_offset() {
        let pos = Pos { byte: 4, bit: 3 };
        let f = Field {
            layout_id: 0,
            offset: 5,
        };
        let c = pos.child(&f);
        assert_eq!(c.byte, 9);
        assert_eq!(c.bit, 3);
    }

    #[test]
    fn child_pos_bit_offset() {
        let pos = Pos { byte: 4, bit: 3 };
        let f = Field {
            layout_id: 0,
            offset: -5,
        };
        let c = pos.child(&f);
        assert_eq!(c.byte, 4);
        assert_eq!(c.bit, 8);
    }

    #[test]
    fn classify_integral() {
        let mut schema = Schema {
            file_version: 1,
            relax_type_checks: false,
            layouts: BTreeMap::new(),
            root_layout: 0,
        };
        schema.layouts.insert(1, integral(8));
        let kind = LayoutKind::of(schema.layout(1).unwrap(), &schema).unwrap();
        assert_eq!(kind, LayoutKind::Integral(8));
    }

    #[test]
    fn classify_optional() {
        let mut schema = Schema {
            file_version: 1,
            relax_type_checks: false,
            layouts: BTreeMap::new(),
            root_layout: 0,
        };
        schema.layouts.insert(1, integral(1));
        schema.layouts.insert(2, integral(8));
        let layout = struct_layout(
            2,
            vec![
                (
                    1,
                    Field {
                        layout_id: 1,
                        offset: -0,
                    },
                ),
                (
                    2,
                    Field {
                        layout_id: 2,
                        offset: 1,
                    },
                ),
            ],
        );
        let kind = LayoutKind::of(&layout, &schema).unwrap();
        assert_eq!(
            kind,
            LayoutKind::Optional {
                value_layout_id: Some(2)
            }
        );
    }

    #[test]
    fn classify_string() {
        let mut schema = Schema {
            file_version: 1,
            relax_type_checks: false,
            layouts: BTreeMap::new(),
            root_layout: 0,
        };
        schema.layouts.insert(1, integral(16));
        schema.layouts.insert(2, integral(16));
        let layout = struct_layout(
            4,
            vec![
                (
                    1,
                    Field {
                        layout_id: 1,
                        offset: 0,
                    },
                ),
                (
                    2,
                    Field {
                        layout_id: 2,
                        offset: 2,
                    },
                ),
            ],
        );
        let kind = LayoutKind::of(&layout, &schema).unwrap();
        assert_eq!(kind, LayoutKind::String);
    }

    #[test]
    fn classify_array() {
        let mut schema = Schema {
            file_version: 1,
            relax_type_checks: false,
            layouts: BTreeMap::new(),
            root_layout: 0,
        };
        schema.layouts.insert(1, integral(16));
        schema.layouts.insert(2, integral(16));
        schema.layouts.insert(3, integral(8));
        let layout = struct_layout(
            4,
            vec![
                (
                    1,
                    Field {
                        layout_id: 1,
                        offset: 0,
                    },
                ),
                (
                    2,
                    Field {
                        layout_id: 2,
                        offset: 2,
                    },
                ),
                (
                    3,
                    Field {
                        layout_id: 3,
                        offset: 0,
                    },
                ),
            ],
        );
        let kind = LayoutKind::of(&layout, &schema).unwrap();
        assert_eq!(kind, LayoutKind::Array { item_layout_id: 3 });
    }

    #[test]
    fn range_view_uses_relative_distance() {
        // String layout at byte 8 with distance=5 means data starts
        // at 8 + 5 = 13. Placing ABC at byte 13 proves the decoder
        // adds distance to the range field's own byte, not to the
        // blob start.
        let mut schema = Schema {
            file_version: 1,
            relax_type_checks: false,
            layouts: BTreeMap::new(),
            root_layout: 0,
        };
        schema.layouts.insert(1, integral(8));
        schema.layouts.insert(2, integral(8));
        let string_layout = struct_layout(
            2,
            vec![
                (
                    1,
                    Field {
                        layout_id: 1,
                        offset: 0,
                    },
                ),
                (
                    2,
                    Field {
                        layout_id: 2,
                        offset: 1,
                    },
                ),
            ],
        );

        let mut blob = vec![0u8; 13];
        blob[8] = 5;
        blob[9] = 3;
        blob.extend_from_slice(b"ABC");

        let frozen = Frozen::new(&schema, &blob);
        let view = frozen
            .read_range(Pos { byte: 8, bit: 0 }, &string_layout)
            .unwrap();
        assert_eq!(view.data_byte, 13);
        assert_eq!(view.count, 3);
        assert_eq!(view.item_layout_id, None);
        assert_eq!(&blob[view.data_byte as usize..], b"ABC");
    }

    #[test]
    fn empty_range_has_no_distance() {
        // String layout at byte 8 with count=0 - distance field must
        // not be read (it could legitimately be zero or garbage).
        let mut schema = Schema {
            file_version: 1,
            relax_type_checks: false,
            layouts: BTreeMap::new(),
            root_layout: 0,
        };
        schema.layouts.insert(1, integral(8));
        schema.layouts.insert(2, integral(8));
        let string_layout = struct_layout(
            2,
            vec![
                (
                    1,
                    Field {
                        layout_id: 1,
                        offset: 0,
                    },
                ),
                (
                    2,
                    Field {
                        layout_id: 2,
                        offset: 1,
                    },
                ),
            ],
        );

        let mut blob = vec![0u8; 10];
        blob[8] = 0xFF; // distance bytes "garbage"
        blob[9] = 0; // count = 0

        let frozen = Frozen::new(&schema, &blob);
        let view = frozen
            .read_range(Pos { byte: 8, bit: 0 }, &string_layout)
            .unwrap();
        assert_eq!(view.count, 0);
        assert_eq!(view.data_byte, 8);
    }

    #[test]
    fn bit_strided_elements_keep_the_byte_anchor() {
        // A nested range resolves its `distance` against `Pos::byte`,
        // so a bit-strided element must leave the byte anchor at the
        // array's data start and accumulate the whole offset in bits.
        let mut schema = Schema {
            file_version: 1,
            relax_type_checks: false,
            layouts: BTreeMap::new(),
            root_layout: 0,
        };
        schema.layouts.insert(1, integral(23));
        let frozen = Frozen::new(&schema, &[]);
        let range = RangeView {
            data_byte: 100,
            count: 4,
            item_layout_id: Some(1),
        };

        for i in 0..4u64 {
            let pos = frozen.element_pos(range, i).unwrap();
            assert_eq!(pos.byte, 100, "element {i} moved the byte anchor");
            assert_eq!(pos.absolute_bit(), 100 * 8 + i * 23);
        }
    }

    #[test]
    fn byte_sized_elements_advance_the_byte_anchor() {
        let mut schema = Schema {
            file_version: 1,
            relax_type_checks: false,
            layouts: BTreeMap::new(),
            root_layout: 0,
        };
        schema.layouts.insert(1, struct_layout(6, vec![]));
        let frozen = Frozen::new(&schema, &[]);
        let range = RangeView {
            data_byte: 8,
            count: 3,
            item_layout_id: Some(1),
        };

        for i in 0..3u64 {
            let pos = frozen.element_pos(range, i).unwrap();
            assert_eq!(pos.byte, 8 + i * 6);
            assert_eq!(pos.bit, 0);
        }
    }
}
