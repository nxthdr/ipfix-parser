//! IPFIX field values
//!
//! Decoded Information Element values, following the abstract data types of
//! [RFC 7012 Section 3.1](https://www.rfc-editor.org/rfc/rfc7012#section-3.1)
//! encoded as per [RFC 7011 Section 6](https://www.rfc-editor.org/rfc/rfc7011#section-6),
//! and the structured data types of [RFC 6313](https://www.rfc-editor.org/rfc/rfc6313).

use super::message::DataRecord;
use std::net::{Ipv4Addr, Ipv6Addr};

/// MAC address (6 bytes) - RFC 7011 Section 6.1.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// Create a new MAC address from 6 bytes
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// Get the MAC address as a byte array
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl std::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

/// NTP Timestamp - RFC 7011 Sections 6.1.9 and 6.1.10
///
/// Used by `dateTimeMicroseconds` and `dateTimeNanoseconds`: seconds since the
/// NTP epoch (1 January 1900) and a binary fraction of a second. For
/// `dateTimeMicroseconds`, the lower 11 bits of the fraction SHOULD be zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NtpTimestamp {
    /// Seconds since 1 January 1900 00:00 UTC
    pub seconds: u32,
    /// Fraction of a second, in units of 2^-32 seconds
    pub fraction: u32,
}

impl NtpTimestamp {
    /// Offset between the NTP epoch (1900) and the UNIX epoch (1970), in seconds
    pub const UNIX_EPOCH_OFFSET: u64 = 2_208_988_800;

    /// Nanoseconds since the UNIX epoch, or `None` if the timestamp is before
    /// 1970. Note that RFC 7011 Section 5.2 does not handle the NTP era
    /// wraparound (2036); this conversion assumes era 0.
    pub fn unix_nanos(&self) -> Option<u64> {
        let secs = (self.seconds as u64).checked_sub(Self::UNIX_EPOCH_OFFSET)?;
        let nanos = ((self.fraction as u64) * 1_000_000_000) >> 32;
        Some(secs * 1_000_000_000 + nanos)
    }
}

/// Structured data type semantic - RFC 6313 Section 4.4
///
/// IANA "IPFIX Structured Data Types Semantics" registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ListSemantic {
    /// 0x00 - none of the elements are actual properties of the Data Record
    NoneOf,
    /// 0x01 - only a single element is an actual property of the Data Record
    ExactlyOneOf,
    /// 0x02 - one or more elements are actual properties of the Data Record
    OneOrMoreOf,
    /// 0x03 - all elements are actual properties of the Data Record
    AllOf,
    /// 0x04 - all elements are actual properties of the Data Record, in order
    Ordered,
    /// 0xFF - the semantic is not specified
    Undefined,
    /// Unassigned value
    Unassigned(u8),
}

impl From<u8> for ListSemantic {
    fn from(value: u8) -> Self {
        match value {
            0x00 => ListSemantic::NoneOf,
            0x01 => ListSemantic::ExactlyOneOf,
            0x02 => ListSemantic::OneOrMoreOf,
            0x03 => ListSemantic::AllOf,
            0x04 => ListSemantic::Ordered,
            0xFF => ListSemantic::Undefined,
            other => ListSemantic::Unassigned(other),
        }
    }
}

impl ListSemantic {
    /// The wire value of the semantic
    pub fn value(&self) -> u8 {
        match self {
            ListSemantic::NoneOf => 0x00,
            ListSemantic::ExactlyOneOf => 0x01,
            ListSemantic::OneOrMoreOf => 0x02,
            ListSemantic::AllOf => 0x03,
            ListSemantic::Ordered => 0x04,
            ListSemantic::Undefined => 0xFF,
            ListSemantic::Unassigned(v) => *v,
        }
    }
}

/// basicList - RFC 6313 Section 4.5.1
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Semantic    |0|          Field ID           |   Element...  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | ...Length     |           basicList Content ...               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              ...                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              ...                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// If the Enterprise bit of the Field ID is set, a four-byte Enterprise Number
/// follows the Element Length (RFC 6313 Figure 2).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BasicList {
    /// Relationship among the list elements
    pub semantic: ListSemantic,
    /// Information Element identifier of the list elements (Enterprise bit
    /// removed)
    pub field_id: u16,
    /// Length of each element, or 65535 if variable-length
    pub element_length: u16,
    /// Private Enterprise Number, present if the Enterprise bit is set
    pub enterprise_number: Option<u32>,
    /// Decoded list elements
    pub basic_list_content: Vec<FieldValue>,
}

/// subTemplateList - RFC 6313 Section 4.5.2
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Semantic    |         Template ID           |     ...       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                subTemplateList Content    ...                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              ...                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SubTemplateList {
    /// Relationship among the Data Records
    pub semantic: ListSemantic,
    /// Template used to decode the content
    pub template_id: u16,
    /// Decoded Data Records
    pub sub_template_list_content: Vec<DataRecord>,
}

/// subTemplateMultiList - RFC 6313 Section 4.5.3
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Semantic   |         Template ID X         |Data Records...|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | ... Length X  |        Data Record X.1 Content ...            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              ...                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      ...      |        Data Record X.2 Content ...            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              ...                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      ...      |        Data Record X.L Content ...            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              ...                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      ...      |         Template ID Y         |Data Records...|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | ... Length Y  |        Data Record  Y.1 Content ...           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              ...                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      ...      |        Data Record Y.2 Content ...            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              ...                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      ...      |        Data Record Y.M Content ...            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              ...                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      ...      |         Template ID Z         |Data Records...|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | ... Length Z  |        Data Record Z.1 Content ...            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              ...                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      ...      |        Data Record Z.2 Content ...            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              ...                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      ...      |        Data Record Z.N Content ...            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              ...                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      ...      |
/// +-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SubTemplateMultiList {
    /// Top-level relationship among the series of Data Records
    pub semantic: ListSemantic,
    /// One entry per Template ID / Data Records Length block
    pub entries: Vec<SubTemplateMultiListEntry>,
}

/// One Template ID / Data Records block of a subTemplateMultiList
/// (RFC 6313 Section 4.5.3)
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SubTemplateMultiListEntry {
    /// Template used to decode the Data Records of this entry
    pub template_id: u16,
    /// Total length of this entry, including the Template ID and the Data
    /// Records Length fields (so at least 4, RFC 6313 Errata 3232)
    pub data_records_length: u16,
    /// Decoded Data Records
    pub data_records: Vec<DataRecord>,
}

/// A decoded Information Element value
///
/// The variant is chosen from the abstract data type of the Information
/// Element in the IANA registry. Values that cannot be decoded with that type
/// (unknown or enterprise-specific Information Element, length not allowed for
/// the type, invalid UTF-8, unknown Template in a subTemplateList, ...) are
/// kept as [`FieldValue::Raw`] rather than failing the whole Message.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FieldValue {
    /// octetArray
    OctetArray(Vec<u8>),
    /// unsigned8, unsigned16, unsigned32, unsigned64 (possibly reduced-size)
    Unsigned(u64),
    /// unsigned256 (RFC 9740), big-endian, left-padded with zeros if
    /// reduced-size
    Unsigned256([u8; 32]),
    /// signed8, signed16, signed32, signed64 (possibly reduced-size, sign
    /// extended as per RFC 7011 Errata 7875)
    Signed(i64),
    /// float32
    Float32(f32),
    /// float64 (possibly reduced-size to float32)
    Float64(f64),
    /// boolean (RFC 7011 Section 6.1.5: 1 = true, 2 = false)
    Boolean(bool),
    /// macAddress
    MacAddress(MacAddress),
    /// string (UTF-8)
    String(String),
    /// dateTimeSeconds: seconds since the UNIX epoch
    DateTimeSeconds(u32),
    /// dateTimeMilliseconds: milliseconds since the UNIX epoch
    DateTimeMilliseconds(u64),
    /// dateTimeMicroseconds: NTP timestamp
    DateTimeMicroseconds(NtpTimestamp),
    /// dateTimeNanoseconds: NTP timestamp
    DateTimeNanoseconds(NtpTimestamp),
    /// ipv4Address
    Ipv4Address(Ipv4Addr),
    /// ipv6Address
    Ipv6Address(Ipv6Addr),
    /// basicList (RFC 6313)
    BasicList(BasicList),
    /// subTemplateList (RFC 6313)
    SubTemplateList(SubTemplateList),
    /// subTemplateMultiList (RFC 6313)
    SubTemplateMultiList(SubTemplateMultiList),
    /// Undecoded value (see the type-level documentation)
    Raw(Vec<u8>),
}
