//! LZ4 and LZ4HC codecs.
//!
//! Framing (DwarFS format spec, "Compression Algorithms"): a 4-byte
//! little-endian uncompressed-size prefix followed by a single LZ4
//! block. LZ4 and LZ4HC differ only in the encoder; the on-disk block
//! format is identical, so a single decoder serves both.
//!
//! Decoding and encoding use different implementations on purpose.
//! `lz4_flex` decodes correctly with no C dependency, which is what a
//! size-constrained reader wants. Both `lz4` and `lz4hc` decode with
//! the same block format, so one decoder serves both.

use crate::Error;

#[cfg(feature = "lz4")]
pub(super) fn decompress(src: &[u8], cap: usize) -> Result<Vec<u8>, Error> {
    if src.len() < 4 {
        return Err(Error::Decode {
            codec: "lz4",
            message: "missing 4-byte size prefix".to_string(),
        });
    }
    let size = u32::from_le_bytes(src[..4].try_into().unwrap()) as usize;
    if size > cap {
        return Err(Error::Decode {
            codec: "lz4",
            message: format!("declared size {size} exceeds cap {cap}"),
        });
    }

    lz4_flex::block::decompress(&src[4..], size).map_err(|e| Error::Decode {
        codec: "lz4",
        message: e.to_string(),
    })
}
