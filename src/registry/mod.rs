//! IANA IPFIX registries
//!
//! Constants and types mirroring the IANA
//! [IP Flow Information Export (IPFIX) Entities](https://www.iana.org/assignments/ipfix/ipfix.xhtml)
//! registries. The Information Element table [`INFORMATION_ELEMENTS`] is
//! generated from the IANA registry (`make registry-update`) and validated
//! against it by `make specs-validate`.

mod information_elements;

pub use information_elements::INFORMATION_ELEMENTS;

/// IPFIX Version Number (IANA "IPFIX Version Numbers" registry)
pub const IPFIX_VERSION: u16 = 10;

/// Set ID of Template Sets (IANA "IPFIX Set IDs" registry)
pub const TEMPLATE_SET_ID: u16 = 2;

/// Set ID of Options Template Sets (IANA "IPFIX Set IDs" registry)
pub const OPTIONS_TEMPLATE_SET_ID: u16 = 3;

/// First Set ID reserved for Data Sets (IANA "IPFIX Set IDs" registry)
pub const MIN_DATA_SET_ID: u16 = 256;

/// Private Enterprise Number signifying "IPFIX Reverse Information Element"
/// (RFC 5103 Section 6.1)
pub const REVERSE_INFORMATION_ELEMENT_PEN: u32 = 29305;

/// IPFIX abstract data type - RFC 7012 Section 3.1
///
/// IANA "IPFIX Information Element Data Types" registry. The discriminant is
/// the IANA registry value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum DataType {
    OctetArray = 0,
    Unsigned8 = 1,
    Unsigned16 = 2,
    Unsigned32 = 3,
    Unsigned64 = 4,
    Signed8 = 5,
    Signed16 = 6,
    Signed32 = 7,
    Signed64 = 8,
    Float32 = 9,
    Float64 = 10,
    Boolean = 11,
    MacAddress = 12,
    String = 13,
    DateTimeSeconds = 14,
    DateTimeMilliseconds = 15,
    DateTimeMicroseconds = 16,
    DateTimeNanoseconds = 17,
    Ipv4Address = 18,
    Ipv6Address = 19,
    BasicList = 20,
    SubTemplateList = 21,
    SubTemplateMultiList = 22,
    Unsigned256 = 23,
}

impl DataType {
    /// All data types, in IANA registry order
    pub const ALL: [DataType; 24] = [
        DataType::OctetArray,
        DataType::Unsigned8,
        DataType::Unsigned16,
        DataType::Unsigned32,
        DataType::Unsigned64,
        DataType::Signed8,
        DataType::Signed16,
        DataType::Signed32,
        DataType::Signed64,
        DataType::Float32,
        DataType::Float64,
        DataType::Boolean,
        DataType::MacAddress,
        DataType::String,
        DataType::DateTimeSeconds,
        DataType::DateTimeMilliseconds,
        DataType::DateTimeMicroseconds,
        DataType::DateTimeNanoseconds,
        DataType::Ipv4Address,
        DataType::Ipv6Address,
        DataType::BasicList,
        DataType::SubTemplateList,
        DataType::SubTemplateMultiList,
        DataType::Unsigned256,
    ];

    /// The data type with this IANA registry value
    pub fn from_value(value: u8) -> Option<DataType> {
        DataType::ALL.get(value as usize).copied()
    }

    /// The IANA name of the data type (e.g. `unsigned32`)
    pub fn name(&self) -> &'static str {
        match self {
            DataType::OctetArray => "octetArray",
            DataType::Unsigned8 => "unsigned8",
            DataType::Unsigned16 => "unsigned16",
            DataType::Unsigned32 => "unsigned32",
            DataType::Unsigned64 => "unsigned64",
            DataType::Signed8 => "signed8",
            DataType::Signed16 => "signed16",
            DataType::Signed32 => "signed32",
            DataType::Signed64 => "signed64",
            DataType::Float32 => "float32",
            DataType::Float64 => "float64",
            DataType::Boolean => "boolean",
            DataType::MacAddress => "macAddress",
            DataType::String => "string",
            DataType::DateTimeSeconds => "dateTimeSeconds",
            DataType::DateTimeMilliseconds => "dateTimeMilliseconds",
            DataType::DateTimeMicroseconds => "dateTimeMicroseconds",
            DataType::DateTimeNanoseconds => "dateTimeNanoseconds",
            DataType::Ipv4Address => "ipv4Address",
            DataType::Ipv6Address => "ipv6Address",
            DataType::BasicList => "basicList",
            DataType::SubTemplateList => "subTemplateList",
            DataType::SubTemplateMultiList => "subTemplateMultiList",
            DataType::Unsigned256 => "unsigned256",
        }
    }

    /// The default (non-reduced) encoded length in octets, or `None` for
    /// variable-length types
    pub fn default_length(&self) -> Option<u16> {
        match self {
            DataType::Unsigned8 | DataType::Signed8 | DataType::Boolean => Some(1),
            DataType::Unsigned16 | DataType::Signed16 => Some(2),
            DataType::Unsigned32
            | DataType::Signed32
            | DataType::Float32
            | DataType::DateTimeSeconds
            | DataType::Ipv4Address => Some(4),
            DataType::MacAddress => Some(6),
            DataType::Unsigned64
            | DataType::Signed64
            | DataType::Float64
            | DataType::DateTimeMilliseconds
            | DataType::DateTimeMicroseconds
            | DataType::DateTimeNanoseconds => Some(8),
            DataType::Ipv6Address => Some(16),
            DataType::Unsigned256 => Some(32),
            DataType::OctetArray
            | DataType::String
            | DataType::BasicList
            | DataType::SubTemplateList
            | DataType::SubTemplateMultiList => None,
        }
    }
}

/// Data type semantics - RFC 7012 Section 3.2
///
/// IANA "IPFIX Information Element Semantics" registry. The discriminant is
/// the IANA registry value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum DataTypeSemantics {
    Default = 0,
    Quantity = 1,
    TotalCounter = 2,
    DeltaCounter = 3,
    Identifier = 4,
    Flags = 5,
    List = 6,
    SnmpCounter = 7,
    SnmpGauge = 8,
}

impl DataTypeSemantics {
    /// All semantics, in IANA registry order
    pub const ALL: [DataTypeSemantics; 9] = [
        DataTypeSemantics::Default,
        DataTypeSemantics::Quantity,
        DataTypeSemantics::TotalCounter,
        DataTypeSemantics::DeltaCounter,
        DataTypeSemantics::Identifier,
        DataTypeSemantics::Flags,
        DataTypeSemantics::List,
        DataTypeSemantics::SnmpCounter,
        DataTypeSemantics::SnmpGauge,
    ];

    /// The semantics with this IANA registry value
    pub fn from_value(value: u8) -> Option<DataTypeSemantics> {
        DataTypeSemantics::ALL.get(value as usize).copied()
    }

    /// The IANA name of the semantics (e.g. `deltaCounter`)
    pub fn name(&self) -> &'static str {
        match self {
            DataTypeSemantics::Default => "default",
            DataTypeSemantics::Quantity => "quantity",
            DataTypeSemantics::TotalCounter => "totalCounter",
            DataTypeSemantics::DeltaCounter => "deltaCounter",
            DataTypeSemantics::Identifier => "identifier",
            DataTypeSemantics::Flags => "flags",
            DataTypeSemantics::List => "list",
            DataTypeSemantics::SnmpCounter => "snmpCounter",
            DataTypeSemantics::SnmpGauge => "snmpGauge",
        }
    }
}

/// Registration status of an Information Element (RFC 7013 Section 5.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Status {
    Current,
    Deprecated,
    Obsolete,
}

/// An IANA-registered Information Element
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InformationElement {
    /// ElementID
    pub id: u16,
    /// Name (e.g. `sourceIPv4Address`)
    pub name: &'static str,
    /// Abstract Data Type
    pub data_type: DataType,
    /// Data Type Semantics, if specified
    pub semantics: Option<DataTypeSemantics>,
    /// Status
    pub status: Status,
    /// Units, if specified
    pub units: Option<&'static str>,
}

/// Look up an IANA Information Element by identifier
pub fn lookup(id: u16) -> Option<&'static InformationElement> {
    INFORMATION_ELEMENTS
        .binary_search_by_key(&id, |ie| ie.id)
        .ok()
        .map(|idx| &INFORMATION_ELEMENTS[idx])
}

/// Look up an IANA Information Element by name
pub fn lookup_by_name(name: &str) -> Option<&'static InformationElement> {
    INFORMATION_ELEMENTS.iter().find(|ie| ie.name == name)
}
