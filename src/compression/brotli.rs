//! Brotli codec.
//!
//! Framing (DwarFS format spec, "Compression Algorithms"): an
//! unsigned LEB128 uncompressed-size prefix followed by a raw brotli
//! stream.

#[cfg(feature = "read")]
use std::io::{self, Read};

use crate::Error;
#[cfg(feature = "read")]
use crate::compression::capped::CappedWriter;

#[cfg(any(feature = "read", test))]
const LEB128_MAX_BYTES: usize = 10;

#[cfg(feature = "read")]
pub(super) fn decompress(src: &[u8], cap: usize) -> Result<Vec<u8>, Error> {
    let (declared, consumed) = read_leb128_u64(src)?;
    if declared > cap as u64 {
        return Err(Error::Decode {
            codec: "brotli",
            message: format!("declared size {declared} exceeds cap {cap}"),
        });
    }

    let mut decoder = brotli::Decompressor::new(&src[consumed..], 4096);
    let mut sink = CappedWriter::with_expected_size(cap, declared as usize);
    let mut buf = [0u8; 8192];
    loop {
        match decoder.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                use std::io::Write as _;
                sink.write_all(&buf[..n]).map_err(map_io_err)?;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(map_io_err(e)),
        }
    }

    Ok(sink.into_inner())
}

#[cfg(feature = "read")]
fn map_io_err(err: io::Error) -> Error {
    Error::Decode {
        codec: "brotli",
        message: err.to_string(),
    }
}

#[cfg(any(feature = "read", test))]
fn read_leb128_u64(src: &[u8]) -> Result<(u64, usize), Error> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in src.iter().take(LEB128_MAX_BYTES).enumerate() {
        let chunk = u64::from(byte & 0x7F);
        result |= chunk.checked_shl(shift).ok_or_else(|| Error::Decode {
            codec: "brotli",
            message: "leb128 size overflow".to_string(),
        })?;
        if byte & 0x80 == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
    }

    Err(Error::Decode {
        codec: "brotli",
        message: "leb128 size truncated or too long".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use brotli::CompressorWriter;
    use std::io::Write;

    fn write_leb128_u64(mut value: u64, out: &mut Vec<u8>) {
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
                out.push(byte);
            } else {
                out.push(byte);
                return;
            }
        }
    }

    fn encode(src: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_leb128_u64(src.len() as u64, &mut out);
        {
            let mut enc = CompressorWriter::new(&mut out, 4096, 6, 22);
            enc.write_all(src).unwrap();
            enc.flush().unwrap();
        }
        out
    }

    #[test]
    fn leb128_roundtrip() {
        for value in [0u64, 1, 127, 128, 16384, u64::from(u32::MAX), u64::MAX] {
            let mut buf = Vec::new();
            write_leb128_u64(value, &mut buf);
            let (parsed, n) = read_leb128_u64(&buf).unwrap();
            assert_eq!(parsed, value);
            assert_eq!(n, buf.len());
        }
    }

    #[test]
    fn leb128_rejects_truncated() {
        let err = read_leb128_u64(&[0x80, 0x80]).unwrap_err();
        assert!(matches!(
            err,
            Error::Decode {
                codec: "brotli",
                ..
            }
        ));
    }

    #[test]
    fn roundtrip_short() {
        let raw = b"hello brotli world".to_vec();
        let enc = encode(&raw);
        let dec = decompress(&enc, 1024).unwrap();
        assert_eq!(dec, raw);
    }

    #[test]
    fn roundtrip_repeated() {
        let raw = vec![0x33u8; 32 * 1024];
        let enc = encode(&raw);
        let dec = decompress(&enc, raw.len()).unwrap();
        assert_eq!(dec, raw);
    }

    #[test]
    fn rejects_size_exceeding_cap() {
        let raw = vec![1u8; 4096];
        let enc = encode(&raw);
        let err = decompress(&enc, 1024).unwrap_err();
        assert!(matches!(
            err,
            Error::Decode {
                codec: "brotli",
                ..
            }
        ));
    }

    #[test]
    fn rejects_garbage_stream() {
        let mut input = Vec::new();
        write_leb128_u64(64, &mut input);
        input.extend([0xFFu8; 32]);
        let err = decompress(&input, 128).unwrap_err();
        assert!(matches!(
            err,
            Error::Decode {
                codec: "brotli",
                ..
            }
        ));
    }
}
