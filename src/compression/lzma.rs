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

#[cfg(feature = "lzma")]
use std::io::{BufReader, Cursor};

use crate::Error;
#[cfg(feature = "lzma")]
use crate::compression::capped::CappedWriter;

#[cfg(feature = "lzma")]
pub(super) fn decompress(src: &[u8], cap: usize) -> Result<Vec<u8>, Error> {
    let mut reader = BufReader::new(Cursor::new(src));
    let mut sink = CappedWriter::new(cap);
    lzma_rs::xz_decompress(&mut reader, &mut sink).map_err(map_decode)?;
    Ok(sink.into_inner())
}

#[cfg(feature = "lzma")]
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
