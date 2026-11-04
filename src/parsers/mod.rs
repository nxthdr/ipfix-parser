//! IPFIX parser
//!
//! This module provides parsing functionality for IPFIX Messages.
//! All data is in network byte order (big-endian) as per RFC 7011 Section 6.1.
//!
//! IPFIX Messages are length-delimited, so parsing works on byte slices and
//! every read is bounds-checked: malformed input returns a [`ParseError`],
//! never panics.

mod decoder;
mod elements;
mod error;
mod value;

pub use decoder::{parse_message, parse_messages, Decoder, DecoderConfig, Transport};
pub use error::{ParseError, Result};

/// Bounds-checked big-endian reader over a byte slice
#[derive(Debug, Clone)]
pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Number of unread octets
    pub(crate) fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Read `n` octets
    pub(crate) fn read_bytes(&mut self, n: usize, context: &'static str) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return Err(ParseError::Truncated {
                context,
                needed: n,
                available: self.remaining(),
            });
        }
        let bytes = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(bytes)
    }

    /// Read all remaining octets
    pub(crate) fn read_rest(&mut self) -> &'a [u8] {
        let bytes = &self.data[self.pos..];
        self.pos = self.data.len();
        bytes
    }

    pub(crate) fn read_u8(&mut self, context: &'static str) -> Result<u8> {
        Ok(self.read_bytes(1, context)?[0])
    }

    pub(crate) fn read_u16(&mut self, context: &'static str) -> Result<u16> {
        let b = self.read_bytes(2, context)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub(crate) fn read_u32(&mut self, context: &'static str) -> Result<u32> {
        let b = self.read_bytes(4, context)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a variable-length Information Element length prefix
    /// (RFC 7011 Section 7): one octet if < 255, otherwise 255 followed by a
    /// two-octet length.
    pub(crate) fn read_variable_length(&mut self, context: &'static str) -> Result<usize> {
        let first = self.read_u8(context)?;
        if first < 255 {
            Ok(first as usize)
        } else {
            Ok(self.read_u16(context)? as usize)
        }
    }

    /// Read a Field Specifier (RFC 7011 Section 3.2), also used by the
    /// basicList header (RFC 6313 Section 4.5.1)
    pub(crate) fn read_field_id(&mut self, context: &'static str) -> Result<(u16, bool)> {
        let raw = self.read_u16(context)?;
        Ok((raw & 0x7FFF, raw & 0x8000 != 0))
    }
}
