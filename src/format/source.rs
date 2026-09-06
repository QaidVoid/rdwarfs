//! Byte sources an image can be read from.
//!
//! The format spec describes this abstraction as a `file_view` and
//! notes the trade-off it exists to express: memory-mapping the whole
//! file is fast but offers no way to handle an I/O error gracefully,
//! typically crashing the process, while reading into buffers is slower
//! but recoverable. A consumer picks the trade-off by picking a source.
//!
//! Sources are owned by the image, so no lifetime propagates into the
//! reader types.

use std::borrow::Cow;
use std::fs::File;

use crate::Error;

/// A random-access source of image bytes.
///
/// Implementations must be cheap to clone-free share across threads
/// because a mounted image serves reads concurrently.
pub trait ImageSource: Send + Sync {
    /// Total number of bytes the source can supply.
    fn len(&self) -> u64;

    /// Whether the source is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Fill `buf` with the bytes at `offset`.
    ///
    /// Returns [`Error::SourceOutOfBounds`] when the requested range is
    /// not entirely backed by the source.
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<(), Error>;

    /// The whole source as one contiguous region, when it has one.
    ///
    /// Sources backed by memory return `Some` so callers can hash and
    /// decode in place. Sources that read positionally return `None`
    /// and callers fall back to [`ImageSource::read_exact_at`].
    fn as_slice(&self) -> Option<&[u8]> {
        None
    }
}

/// Bounds check shared by every in-memory source.
fn slice_at(bytes: &[u8], buf_len: usize, offset: u64) -> Result<&[u8], Error> {
    let start = usize::try_from(offset).map_err(|_| Error::SourceOutOfBounds {
        offset,
        len: buf_len as u64,
        source_len: bytes.len() as u64,
    })?;
    let end = start
        .checked_add(buf_len)
        .filter(|end| *end <= bytes.len())
        .ok_or(Error::SourceOutOfBounds {
            offset,
            len: buf_len as u64,
            source_len: bytes.len() as u64,
        })?;
    Ok(&bytes[start..end])
}

impl ImageSource for Vec<u8> {
    fn len(&self) -> u64 {
        self.as_slice().len() as u64
    }

    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        buf.copy_from_slice(slice_at(self, buf.len(), offset)?);
        Ok(())
    }

    fn as_slice(&self) -> Option<&[u8]> {
        Some(self)
    }
}

/// A source that reads positionally from an open file.
///
/// Nothing is mapped, so an I/O error surfaces as an error rather than
/// a fault. This is the source to use when the image lives inside a
/// larger file that the process cannot afford to map.
pub struct FileSource {
    file: File,
    len: u64,
}

impl FileSource {
    /// Wrap an open file, taking its current length as the source
    /// length.
    pub fn new(file: File) -> Result<Self, Error> {
        let len = file.metadata()?.len();
        Ok(Self { file, len })
    }

    /// Open `path` for reading and wrap it.
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> Result<Self, Error> {
        Self::new(File::open(path)?)
    }
}

impl ImageSource for FileSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        let end = offset
            .checked_add(buf.len() as u64)
            .filter(|end| *end <= self.len);
        if end.is_none() {
            return Err(Error::SourceOutOfBounds {
                offset,
                len: buf.len() as u64,
                source_len: self.len,
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            self.file.read_exact_at(buf, offset)?;
        }
        #[cfg(not(unix))]
        {
            use std::io::{Read, Seek, SeekFrom};
            let mut file = &self.file;
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(buf)?;
        }
        Ok(())
    }
}

/// A source restricted to a byte range of another source.
///
/// An image embedded in a larger file is bounded on both sides: a
/// prefix before it and unrelated data after it. Section walking stops
/// at the end of the source and the section index is found from the
/// last eight bytes of it, so confining the range is what makes an
/// embedded image readable at all.
pub struct WindowedSource<S> {
    inner: S,
    offset: u64,
    len: u64,
}

impl<S: ImageSource> WindowedSource<S> {
    /// Restrict `inner` to `len` bytes starting at `offset`.
    ///
    /// Returns [`Error::SourceOutOfBounds`] when the window is not
    /// entirely backed by `inner`.
    pub fn new(inner: S, offset: u64, len: u64) -> Result<Self, Error> {
        let source_len = inner.len();
        let fits = offset.checked_add(len).is_some_and(|end| end <= source_len);
        if !fits {
            return Err(Error::SourceOutOfBounds {
                offset,
                len,
                source_len,
            });
        }
        Ok(Self { inner, offset, len })
    }
}

impl<S: ImageSource> ImageSource for WindowedSource<S> {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        let within = offset
            .checked_add(buf.len() as u64)
            .is_some_and(|end| end <= self.len);
        if !within {
            return Err(Error::SourceOutOfBounds {
                offset,
                len: buf.len() as u64,
                source_len: self.len,
            });
        }
        self.inner.read_exact_at(buf, self.offset + offset)
    }

    fn as_slice(&self) -> Option<&[u8]> {
        let bytes = self.inner.as_slice()?;
        let start = usize::try_from(self.offset).ok()?;
        let end = start.checked_add(usize::try_from(self.len).ok()?)?;
        bytes.get(start..end)
    }
}

#[cfg(feature = "mmap")]
impl ImageSource for memmap2::Mmap {
    fn len(&self) -> u64 {
        self.as_ref().len() as u64
    }

    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        buf.copy_from_slice(slice_at(self, buf.len(), offset)?);
        Ok(())
    }

    fn as_slice(&self) -> Option<&[u8]> {
        Some(self)
    }
}

/// Read `len` bytes at `offset` from `source`, borrowing when possible.
pub(crate) fn read_range(
    source: &dyn ImageSource,
    offset: u64,
    len: u64,
) -> Result<Cow<'_, [u8]>, Error> {
    let out_of_bounds = || Error::SourceOutOfBounds {
        offset,
        len,
        source_len: source.len(),
    };
    let end = offset.checked_add(len).ok_or_else(out_of_bounds)?;
    if end > source.len() {
        return Err(out_of_bounds());
    }
    let len = usize::try_from(len).map_err(|_| out_of_bounds())?;

    if let Some(bytes) = source.as_slice() {
        let start = usize::try_from(offset).map_err(|_| out_of_bounds())?;
        return Ok(Cow::Borrowed(&bytes[start..start + len]));
    }
    let mut buf = vec![0u8; len];
    source.read_exact_at(&mut buf, offset)?;
    Ok(Cow::Owned(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vec_source_reads_at_offset() {
        let data = b"0123456789".to_vec();
        let mut buf = [0u8; 4];
        data.read_exact_at(&mut buf, 3).unwrap();
        assert_eq!(&buf, b"3456");
        assert_eq!(ImageSource::len(&data), 10);
        assert_eq!(ImageSource::as_slice(&data).unwrap().len(), 10);
    }

    #[test]
    fn vec_source_rejects_out_of_bounds() {
        let data = b"0123".to_vec();
        let mut buf = [0u8; 4];
        let err = data.read_exact_at(&mut buf, 1).unwrap_err();
        assert!(matches!(
            err,
            Error::SourceOutOfBounds {
                offset: 1,
                len: 4,
                source_len: 4
            }
        ));
    }

    #[test]
    fn file_source_matches_vec_source() {
        let path = std::env::temp_dir().join("rdwarfs-file-source.bin");
        let data: Vec<u8> = (0u8..=255).collect();
        std::fs::write(&path, &data).unwrap();

        let file = FileSource::open(&path).unwrap();
        assert_eq!(file.len(), 256);
        assert!(file.as_slice().is_none());

        let mut from_file = [0u8; 16];
        let mut from_vec = [0u8; 16];
        file.read_exact_at(&mut from_file, 100).unwrap();
        data.read_exact_at(&mut from_vec, 100).unwrap();
        assert_eq!(from_file, from_vec);

        let mut overrun = [0u8; 8];
        assert!(file.read_exact_at(&mut overrun, 250).is_err());

        let _ = std::fs::remove_file(&path);
    }
}
