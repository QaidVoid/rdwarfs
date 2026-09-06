//! `NONE` codec: payload bytes are returned verbatim.

#[cfg(feature = "read")]
use crate::Error;

#[cfg(feature = "read")]
pub(super) fn decompress(src: &[u8], cap: usize) -> Result<Vec<u8>, Error> {
    if src.len() > cap {
        return Err(Error::Decode {
            codec: "none",
            message: format!("payload size {} exceeds cap {}", src.len(), cap),
        });
    }
    Ok(src.to_vec())
}

#[cfg(all(test, feature = "read"))]
mod tests {
    use super::*;

    #[test]
    fn passes_through() {
        assert_eq!(decompress(b"hello", 1024).unwrap(), b"hello");
    }

    #[test]
    fn enforces_cap() {
        let err = decompress(b"abcdef", 3).unwrap_err();
        assert!(matches!(err, Error::Decode { codec: "none", .. }));
    }
}
