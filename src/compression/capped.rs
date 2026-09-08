//! Hostile-input output cap: a [`std::io::Write`] sink that errors
//! the instant the buffered output exceeds a configured cap.
//!
//! Decoders for compressed sections are passed an untrusted byte
//! stream that can decompress to far more bytes than the original.
//! Wrapping the decoder's output sink in a `CappedWriter` bounds the
//! peak allocation independently of the codec's behavior.

use std::io;

/// A capped buffer that grows as bytes are written but rejects any
/// write that would exceed the configured cap.
pub struct CappedWriter {
    buf: Vec<u8>,
    cap: usize,
}

impl CappedWriter {
    /// Create a new writer that accepts up to `cap` bytes total.
    pub fn new(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap.min(64 * 1024)),
            cap,
        }
    }

    /// Reserve for an output size the caller already knows, so a large
    /// payload does not grow its buffer a reallocation at a time. The
    /// cap is still enforced, and the hint is clamped to it so a
    /// declared size cannot drive the allocation.
    pub fn with_expected_size(cap: usize, expected: usize) -> Self {
        Self {
            buf: Vec::with_capacity(expected.min(cap)),
            cap,
        }
    }

    /// Consume the writer and return the buffered bytes.
    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }

    /// Borrow the buffered bytes without consuming the writer.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Number of bytes written so far.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// True when no bytes have been written.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl io::Write for CappedWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.buf.len().saturating_add(data.len()) > self.cap {
            return Err(io::Error::other(format!(
                "output exceeded cap of {} bytes",
                self.cap
            )));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn accepts_writes_within_cap() {
        let mut w = CappedWriter::new(16);
        w.write_all(b"hello").unwrap();
        w.write_all(b" world").unwrap();
        assert_eq!(w.as_slice(), b"hello world");
        assert_eq!(w.len(), 11);
    }

    #[test]
    fn rejects_exceeding_cap_in_one_write() {
        let mut w = CappedWriter::new(4);
        assert!(w.write_all(b"toolong").is_err());
    }

    #[test]
    fn rejects_exceeding_cap_across_writes() {
        let mut w = CappedWriter::new(8);
        w.write_all(b"abcdef").unwrap();
        assert!(w.write_all(b"ghi").is_err());
    }

    #[test]
    fn empty_writer() {
        let w = CappedWriter::new(0);
        assert!(w.is_empty());
    }
}
