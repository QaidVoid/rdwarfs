//! FSST (Fast Static Symbol Table) decoder for compact string tables.
//!
//! FSST maps single-byte codes to short symbols (1 to 8 bytes). The
//! special code `0xFF` is an escape: the next byte is a literal, not
//! a code. Decoding is therefore a tight per-byte loop over the
//! compressed payload, looking up each code in the symbol table.
//!
//! Symbol-table framing follows the FSST reference implementation's
//! `fsst_export`
//! reference implementation: 8 bytes of version metadata, one byte
//! recording the `zeroTerminated` flag, an 8-byte length histogram
//! `lenHisto[0..8]`, and then symbol bytes serialized in order of
//! length 2, 3, 4, 5, 6, 7, 8, 1 (one-byte symbols last). The histogram
//! entry `lenHisto[i]` records the number of symbols of length
//! `((i + 1) & 7) + 1`, i.e. 1-byte symbols are counted in slot 0 and
//! appended after the multi-byte symbols.
//!
//! Source: Apache-2.0 `fsst/libfsst.cpp` (`fsst_export` /
//! `fsst_import`).

use crate::Error;

/// Escape byte: the next byte in the compressed stream is a literal.
pub const FSST_ESC: u8 = 0xFF;

pub(crate) const FSST_VERSION: u32 = 20_190_218;
const HEADER_LEN: usize = 17;
const NUM_CODES: usize = 256;

/// Decoded FSST symbol table. Symbol bytes are stored contiguously in
/// `symbols` keyed by the code's `(offset, len)` pair.
#[derive(Debug, Clone)]
pub struct SymTable {
    /// Concatenated symbol bytes.
    symbols: Vec<u8>,
    /// Per-code (offset into [`SymTable::symbols`], length).
    spans: [(u32, u8); NUM_CODES],
    /// Whether the symbol table was built in zero-terminated mode.
    zero_terminated: bool,
}

impl SymTable {
    /// Parse a serialized FSST symbol table. Returns the table plus
    /// the number of input bytes consumed (the caller may have
    /// trailing bytes belonging to a different field).
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), Error> {
        if bytes.len() < HEADER_LEN {
            return Err(decode("symbol table header too short".to_string()));
        }

        let version_word = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let version_high = (version_word >> 32) as u32;
        if version_high != FSST_VERSION {
            return Err(decode(format!(
                "unexpected FSST version {version_high:#010x}"
            )));
        }

        let zero_terminated = (bytes[8] & 1) != 0;
        let len_histo: [u8; 8] = bytes[9..17].try_into().unwrap();

        let mut symbols = Vec::new();
        let mut spans = [(0u32, 0u8); NUM_CODES];

        // In zero-terminated mode, code 0 is reserved for the empty
        // string and the 1-byte symbol count is reduced by one because
        // that code is not stored in the symbol stream.
        let mut code: usize = if zero_terminated { 1 } else { 0 };
        if zero_terminated {
            spans[0] = (0, 0);
        }
        let mut effective_histo = len_histo;
        if zero_terminated {
            effective_histo[0] = effective_histo[0].saturating_sub(1);
        }

        let mut pos = HEADER_LEN;
        // Iteration order matches the FSST encoder: l = 1..=8
        // produces lengths 2, 3, 4, 5, 6, 7, 8, 1 (modulo 8).
        for l in 1u8..=8 {
            let slot = (l & 7) as usize;
            let symbol_len = (slot as u8) + 1;
            let count = effective_histo[slot] as usize;
            for _ in 0..count {
                if code >= NUM_CODES {
                    return Err(decode("too many FSST symbols".to_string()));
                }
                let end = pos
                    .checked_add(symbol_len as usize)
                    .ok_or_else(|| decode("symbol overflow".to_string()))?;
                if end > bytes.len() {
                    return Err(decode("symbol bytes truncated".to_string()));
                }
                let start = u32::try_from(symbols.len())
                    .map_err(|_| decode("symbol table too large".to_string()))?;
                symbols.extend_from_slice(&bytes[pos..end]);
                spans[code] = (start, symbol_len);
                code += 1;
                pos = end;
            }
        }

        // Unused codes decode to nothing; an escape byte handles
        // literals.
        Ok((
            Self {
                symbols,
                spans,
                zero_terminated,
            },
            pos,
        ))
    }

    /// Number of bytes of serialized header + symbols this table
    /// occupies. Equal to the second tuple element returned by
    /// [`SymTable::parse`].
    pub fn header_len() -> usize {
        HEADER_LEN
    }

    /// Whether the table was created in zero-terminated mode.
    pub fn zero_terminated(&self) -> bool {
        self.zero_terminated
    }

    /// Symbol bytes mapped to `code`. Returns `&[]` for unused codes.
    fn symbol(&self, code: u8) -> &[u8] {
        let (start, len) = self.spans[code as usize];
        let end = start as usize + len as usize;
        &self.symbols[start as usize..end]
    }

    /// Decode a single compressed string.
    pub fn decode(&self, compressed: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        let mut i = 0;
        while i < compressed.len() {
            let byte = compressed[i];
            i += 1;
            if byte == FSST_ESC {
                if i >= compressed.len() {
                    return Err(decode("FSST escape at end of input".to_string()));
                }
                out.push(compressed[i]);
                i += 1;
            } else {
                let symbol = self.symbol(byte);
                if symbol.is_empty() {
                    return Err(decode(format!(
                        "FSST code {byte:#04x} references unused symbol"
                    )));
                }
                out.extend_from_slice(symbol);
            }
        }
        Ok(())
    }

    /// Convenience wrapper that allocates the output vector.
    pub fn decode_to_vec(&self, compressed: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(compressed.len() * 2);
        self.decode(compressed, &mut out)?;
        Ok(out)
    }
}

fn decode(message: String) -> Error {
    Error::Decode {
        codec: "fsst",
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a symbol table blob that maps codes 0..N to short
    /// symbols. The encoding mirrors the FSST `fsst_export`:
    /// `histo[0]` counts 1-byte symbols, `histo[k]` (k=1..7) counts
    /// (k+1)-byte symbols, and symbol bytes are appended in order of
    /// length 2, 3, ..., 8, then 1.
    fn build_test_blob(symbols: &[&[u8]]) -> Vec<u8> {
        let mut histo = [0u8; 8];
        for s in symbols {
            assert!(!s.is_empty() && s.len() <= 8);
            histo[s.len() - 1] += 1;
        }
        let mut buf = Vec::new();
        let version = (u64::from(FSST_VERSION)) << 32;
        buf.extend(version.to_le_bytes());
        buf.push(0); // zeroTerminated
        buf.extend(histo);

        for l in 1u8..=8 {
            let want = (l & 7) + 1;
            for s in symbols.iter().filter(|s| s.len() as u8 == want) {
                buf.extend_from_slice(s);
            }
        }
        buf
    }

    #[test]
    fn parses_and_decodes_short_table() {
        let blob = build_test_blob(&[b"ab", b"cd", b"q"]);
        let (table, used) = SymTable::parse(&blob).unwrap();
        assert_eq!(used, blob.len());

        // codes assigned by length order 2,3,4,...,8,1: first two
        // codes are 2-byte symbols (ab, cd), then 1-byte (q).
        let mut out = Vec::new();
        table.decode(&[0, 1, 2], &mut out).unwrap();
        assert_eq!(out, b"abcdq");
    }

    #[test]
    fn escape_byte_is_literal() {
        let blob = build_test_blob(&[b"hi"]);
        let (table, _) = SymTable::parse(&blob).unwrap();
        let out = table.decode_to_vec(&[0, FSST_ESC, b'Z', 0]).unwrap();
        assert_eq!(out, b"hiZhi");
    }

    #[test]
    fn rejects_wrong_version() {
        let mut blob = build_test_blob(&[b"x"]);
        blob[4] = 0x00;
        let err = SymTable::parse(&blob).unwrap_err();
        assert!(matches!(err, Error::Decode { codec: "fsst", .. }));
    }

    #[test]
    fn rejects_truncated_symbols() {
        let mut blob = build_test_blob(&[b"ab"]);
        blob.pop();
        let err = SymTable::parse(&blob).unwrap_err();
        assert!(matches!(err, Error::Decode { codec: "fsst", .. }));
    }

    #[test]
    fn unused_code_is_an_error() {
        let blob = build_test_blob(&[b"a"]);
        let (table, _) = SymTable::parse(&blob).unwrap();
        let err = table.decode_to_vec(&[5]).unwrap_err();
        assert!(matches!(err, Error::Decode { codec: "fsst", .. }));
    }
}
