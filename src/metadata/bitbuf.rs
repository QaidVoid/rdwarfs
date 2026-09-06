//! LSB-first bit reader for the Frozen2 payload.
//!
//! Frozen2 packs primitive values bit-by-bit, low-bit-first within
//! each byte: bit offset 0 is the least-significant bit of byte 0,
//! bit offset 8 is the least-significant bit of byte 1, and so on.
//! Reads of up to 64 bits are supported and may straddle up to nine
//! bytes when a request starts mid-byte.

use crate::Error;

/// A read-only view over a byte slice that addresses individual bits
/// in LSB-first order.
#[derive(Debug, Clone, Copy)]
pub struct BitBuf<'a> {
    bytes: &'a [u8],
}

impl<'a> BitBuf<'a> {
    /// Wrap a byte slice. The buffer is purely a view; no allocation.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Borrow the backing byte slice.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Total bit length addressable by this buffer.
    pub fn bit_len(&self) -> u64 {
        (self.bytes.len() as u64) * 8
    }

    /// Read `num_bits` (0..=64) starting at `bit_offset`, returning
    /// the value zero-extended into a `u64`.
    pub fn read_u64(&self, bit_offset: u64, num_bits: u32) -> Result<u64, Error> {
        if num_bits == 0 {
            return Ok(0);
        }
        if num_bits > 64 {
            return Err(decode(format!("requested {num_bits} bits, max is 64")));
        }
        let end_bit = bit_offset
            .checked_add(u64::from(num_bits))
            .ok_or_else(|| decode("bit offset overflow".to_string()))?;
        if end_bit > self.bit_len() {
            return Err(decode(format!(
                "read of {num_bits} bits at {bit_offset} runs past end ({} bits)",
                self.bit_len()
            )));
        }

        let byte_off = (bit_offset / 8) as usize;
        let shift = (bit_offset % 8) as u32;
        let span = (shift + num_bits).div_ceil(8) as usize;

        let mut acc: u128 = 0;
        for i in 0..span {
            acc |= u128::from(self.bytes[byte_off + i]) << (i * 8);
        }

        let mask = if num_bits == 64 {
            u128::from(u64::MAX)
        } else {
            (1u128 << num_bits) - 1
        };
        Ok(((acc >> shift) & mask) as u64)
    }

    /// Read a single bit (0 or 1) as a boolean.
    pub fn read_bool(&self, bit_offset: u64) -> Result<bool, Error> {
        Ok(self.read_u64(bit_offset, 1)? != 0)
    }

    /// Read `num_bits` and interpret the top bit as a sign bit.
    ///
    /// For `num_bits == 0` returns 0. Up to 63 sign-extended bits are
    /// supported (an i64 has 63 magnitude bits + 1 sign bit).
    pub fn read_i64(&self, bit_offset: u64, num_bits: u32) -> Result<i64, Error> {
        if num_bits == 0 {
            return Ok(0);
        }
        if num_bits > 64 {
            return Err(decode(format!("requested {num_bits} signed bits, max 64")));
        }
        let raw = self.read_u64(bit_offset, num_bits)?;
        if num_bits == 64 {
            return Ok(raw as i64);
        }
        let sign_bit = 1u64 << (num_bits - 1);
        if raw & sign_bit != 0 {
            let extended = raw | (!0u64 << num_bits);
            Ok(extended as i64)
        } else {
            Ok(raw as i64)
        }
    }
}

fn decode(message: String) -> Error {
    Error::Decode {
        codec: "frozen2-bitbuf",
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_within_one_byte() {
        let b = BitBuf::new(&[0b1101_0110]);
        assert_eq!(b.read_u64(0, 1).unwrap(), 0);
        assert_eq!(b.read_u64(1, 1).unwrap(), 1);
        assert_eq!(b.read_u64(0, 4).unwrap(), 0b0110);
        assert_eq!(b.read_u64(4, 4).unwrap(), 0b1101);
        assert_eq!(b.read_u64(0, 8).unwrap(), 0b1101_0110);
    }

    #[test]
    fn reads_across_byte_boundary() {
        let b = BitBuf::new(&[0xFF, 0x0F]);
        assert_eq!(b.read_u64(4, 8).unwrap(), 0xFF);
        assert_eq!(b.read_u64(0, 12).unwrap(), 0x0FFF);
        assert_eq!(b.read_u64(0, 16).unwrap(), 0x0FFF);
    }

    #[test]
    fn reads_64_bit_aligned_and_unaligned() {
        let value: u64 = 0xDEAD_BEEF_CAFE_BABE;
        let mut buf = Vec::with_capacity(16);
        buf.extend([0u8; 4]);
        buf.extend(value.to_le_bytes());
        buf.extend([0u8; 4]);

        let b = BitBuf::new(&buf);
        assert_eq!(b.read_u64(32, 64).unwrap(), value);

        let bit_offset = 32 + 3;
        let shifted: u128 = u128::from(value) << 3;
        let bytes: [u8; 16] = shifted.to_le_bytes();
        let mut buf2 = Vec::with_capacity(16);
        buf2.extend([0u8; 4]);
        buf2.extend(&bytes);
        let b2 = BitBuf::new(&buf2);
        assert_eq!(b2.read_u64(bit_offset, 64).unwrap(), value);
    }

    #[test]
    fn out_of_bounds_errors() {
        let b = BitBuf::new(&[0xFFu8; 2]);
        assert!(b.read_u64(8, 16).is_err());
        assert!(b.read_u64(0, 65).is_err());
    }

    #[test]
    fn zero_bits_is_zero() {
        let b = BitBuf::new(&[0xFF]);
        assert_eq!(b.read_u64(3, 0).unwrap(), 0);
    }

    #[test]
    fn sign_extends_negative_values() {
        let b = BitBuf::new(&[0xFC]);
        assert_eq!(b.read_i64(0, 3).unwrap(), -4);
        assert_eq!(b.read_i64(0, 4).unwrap(), -4);
        assert_eq!(b.read_i64(2, 6).unwrap(), -1);
    }

    #[test]
    fn sign_extension_preserves_positive() {
        let b = BitBuf::new(&[0x05]);
        assert_eq!(b.read_i64(0, 4).unwrap(), 5);
    }

    #[test]
    fn read_bool_basic() {
        let b = BitBuf::new(&[0b0000_0101]);
        assert!(b.read_bool(0).unwrap());
        assert!(!b.read_bool(1).unwrap());
        assert!(b.read_bool(2).unwrap());
    }
}
