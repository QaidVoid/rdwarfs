//! LZMA codec, framed as an xz container stream.
//!
//! DwarFS uses the xz container framing for its LZMA sections (format
//! spec, "Compression Algorithms").
//!
//! Decoding and encoding use different implementations on purpose.
//! `lzma_rs` decodes correctly with no C dependency, which is what a
//! size-constrained reader wants, but its encoder is minimal: on a
//! 141 MiB tree it produced 144 MiB where the reference implementation
//! produced 17 MiB, and it accepts no level. Encoding therefore goes

#[cfg(all(feature = "lzma", not(feature = "lzma-native")))]
use std::io::{BufReader, Cursor};

use crate::Error;
#[cfg(all(feature = "lzma", not(feature = "lzma-native")))]
use crate::compression::capped::CappedWriter;
#[cfg(all(feature = "lzma", not(feature = "lzma-native")))]
use crate::compression::capped::PrefixWriter;

#[cfg(all(feature = "lzma", not(feature = "lzma-native")))]
pub(super) fn decompress(src: &[u8], cap: usize) -> Result<Vec<u8>, Error> {
    let mut reader = BufReader::new(Cursor::new(src));
    let mut sink = CappedWriter::new(cap);
    lzma_rs::xz_decompress(&mut reader, &mut sink).map_err(map_decode)?;
    Ok(sink.into_inner())
}

#[cfg(all(feature = "lzma", not(feature = "lzma-native")))]
fn map_decode(err: lzma_rs::error::Error) -> Error {
    let message = match err {
        lzma_rs::error::Error::IoError(e) => format!("io: {e}"),
        other => other.to_string(),
    };
    Error::Decode {
        codec: "lzma",
        message,
    }
}

/// Decode at least `needed` bytes from the front of the stream.
///
/// `lzma_rs` decodes a whole stream whatever the sink does, so this
/// saves nothing here; it exists so the codec answers the call. Build
/// with `lzma-native` for a decoder that actually stops.
#[cfg(all(feature = "lzma", not(feature = "lzma-native")))]
pub(super) fn decompress_prefix(src: &[u8], needed: usize) -> Result<Vec<u8>, Error> {
    let mut reader = BufReader::new(Cursor::new(src));
    let mut sink = PrefixWriter::new(needed);
    match lzma_rs::xz_decompress(&mut reader, &mut sink) {
        Ok(()) => Ok(sink.into_inner()),
        Err(lzma_rs::error::Error::IoError(e)) if PrefixWriter::is_complete(&e) => {
            Ok(sink.into_inner())
        }
        Err(e) => Err(map_decode(e)),
    }
}

#[cfg(feature = "lzma-native")]
pub(super) fn decompress(src: &[u8], cap: usize) -> Result<Vec<u8>, Error> {
    read_stream(src, cap, cap)
}

/// Decode at least `needed` bytes, stopping once the prefix is filled.
#[cfg(feature = "lzma-native")]
pub(super) fn decompress_prefix(src: &[u8], needed: usize) -> Result<Vec<u8>, Error> {
    read_stream(src, needed, needed)
}

/// Pull from liblzma until `want` bytes are out or the stream ends.
#[cfg(feature = "lzma-native")]
fn read_stream(src: &[u8], want: usize, cap: usize) -> Result<Vec<u8>, Error> {
    use std::io::Read as _;
    let fail = |e: std::io::Error| Error::Decode {
        codec: "lzma",
        message: e.to_string(),
    };
    let mut decoder = liblzma::read::XzDecoder::new(src);
    let mut out = Vec::with_capacity(want.min(cap).min(64 << 20));
    let mut chunk = vec![0u8; 256 * 1024];
    while out.len() < want {
        let room = (want - out.len()).min(chunk.len());
        let n = decoder.read(&mut chunk[..room]).map_err(fail)?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
        if out.len() > cap {
            return Err(Error::Decode {
                codec: "lzma",
                message: format!("output exceeded cap of {cap} bytes"),
            });
        }
    }
    Ok(out)
}
