//! ZSTD codec.
//!
//! Framing: a single ZSTD frame carrying the content size in its
//! frame header (DwarFS format spec, "Compression Algorithms").
//!
//! A frame that declares its size decodes in one shot into an
//! exactly-sized buffer. A frame that does not falls back to streaming
//! through a [`CappedWriter`], so a hostile frame cannot allocate
//! beyond the caller's cap either way.

#[cfg(feature = "read")]
use std::io;

use crate::Error;
#[cfg(feature = "read")]
use crate::compression::capped::CappedWriter;

#[cfg(feature = "read")]
pub(super) fn decompress(src: &[u8], cap: usize) -> Result<Vec<u8>, Error> {
    // Streaming decode moves output through an 8 KiB intermediate and
    // grows the destination as it goes. Decoding a declared-size frame
    // straight into an exact buffer is several times faster, and block
    // payloads always declare their size.
    if let Ok(Some(size)) = zstd::zstd_safe::get_frame_content_size(src) {
        let size = usize::try_from(size).unwrap_or(usize::MAX);
        if size > cap {
            return Err(Error::Decode {
                codec: "zstd",
                message: format!("frame declares {size} bytes, cap is {cap}"),
            });
        }
        return zstd::bulk::decompress(src, size).map_err(map_decode);
    }
    let mut decoder = zstd::Decoder::with_buffer(src).map_err(map_decode)?;
    let mut sink = CappedWriter::new(cap);
    io::copy(&mut decoder, &mut sink).map_err(map_decode)?;
    Ok(sink.into_inner())
}

#[cfg(feature = "read")]
fn map_decode(err: io::Error) -> Error {
    Error::Decode {
        codec: "zstd",
        message: err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(src: &[u8], level: i32) -> Vec<u8> {
        zstd::encode_all(src, level).expect("zstd encode")
    }

    #[test]
    fn roundtrip_short() {
        let raw = b"the quick brown fox jumps over the lazy dog".to_vec();
        let enc = encode(&raw, 3);
        let dec = decompress(&enc, 1024).unwrap();
        assert_eq!(dec, raw);
    }

    #[test]
    fn roundtrip_repeated() {
        let raw = vec![0x5Au8; 64 * 1024];
        let enc = encode(&raw, 19);
        assert!(enc.len() < raw.len() / 4);
        let dec = decompress(&enc, raw.len()).unwrap();
        assert_eq!(dec, raw);
    }

    #[test]
    fn empty_input() {
        let enc = encode(b"", 1);
        assert!(decompress(&enc, 16).unwrap().is_empty());
    }

    #[test]
    fn rejects_when_output_exceeds_cap() {
        let raw = vec![0u8; 8192];
        let enc = encode(&raw, 1);
        let err = decompress(&enc, 1024).unwrap_err();
        assert!(matches!(err, Error::Decode { codec: "zstd", .. }));
    }

    #[test]
    fn rejects_truncated_frame() {
        let raw = b"some bytes to be compressed".to_vec();
        let enc = encode(&raw, 3);
        let err = decompress(&enc[..enc.len() / 2], 1024).unwrap_err();
        assert!(matches!(err, Error::Decode { codec: "zstd", .. }));
    }

    #[test]
    fn rejects_garbage() {
        let err = decompress(&[0u8; 16], 64).unwrap_err();
        assert!(matches!(err, Error::Decode { codec: "zstd", .. }));
    }
}
