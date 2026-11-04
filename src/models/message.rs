//! IPFIX message structures
//!
//! This module contains the data structures representing IPFIX Messages, Sets,
//! Template Records and Data Records as defined in
//! [RFC 7011 Section 3](https://www.rfc-editor.org/rfc/rfc7011#section-3).

use super::value::FieldValue;
use crate::registry::{self, InformationElement};

/// IPFIX Message Header - RFC 7011 Section 3.1
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |       Version Number          |            Length             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Export Time                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Sequence Number                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Observation Domain ID                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MessageHeader {
    /// Version of IPFIX to which this Message conforms (0x000a)
    pub version: u16,
    /// Total length of the IPFIX Message, in octets, including the Message
    /// Header and Set(s)
    pub length: u16,
    /// Time at which the IPFIX Message Header leaves the Exporter, in seconds
    /// since the UNIX epoch
    pub export_time: u32,
    /// Sequence counter (modulo 2^32) of all IPFIX Data Records sent in the
    /// current stream from the current Observation Domain, prior to this
    /// Message (RFC 7011 Errata 4396)
    pub sequence_number: u32,
    /// Identifier of the Observation Domain, locally unique to the Exporting
    /// Process
    pub observation_domain_id: u32,
}

/// Set Header - RFC 7011 Section 3.3.2
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Set ID               |          Length               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SetHeader {
    /// Identifies the Set: 2 = Template Set, 3 = Options Template Set,
    /// 256 and above = Data Set (the Set ID is the Template ID)
    pub set_id: u16,
    /// Total length of the Set, in octets, including the Set Header, all
    /// records, and the optional padding
    pub length: u16,
}

/// Field Specifier - RFC 7011 Section 3.2
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |E|  Information Element ident. |        Field Length           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Enterprise Number                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// The Enterprise bit (`E`) is not stored separately: it is set if and only if
/// `enterprise_number` is `Some`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FieldSpecifier {
    /// Information Element identifier (15 bits, Enterprise bit removed)
    pub information_element_identifier: u16,
    /// Length of the encoded Information Element, in octets.
    /// [`VARIABLE_LENGTH`](Self::VARIABLE_LENGTH) (65535) means variable-length.
    pub field_length: u16,
    /// IANA Private Enterprise Number, present if the Enterprise bit is set
    pub enterprise_number: Option<u32>,
}

impl FieldSpecifier {
    /// Field Length value reserved for variable-length Information Elements
    /// (RFC 7011 Section 7)
    pub const VARIABLE_LENGTH: u16 = 65535;

    /// Whether the Information Element is variable-length
    pub fn is_variable_length(&self) -> bool {
        self.field_length == Self::VARIABLE_LENGTH
    }

    /// Whether the Field Specifier refers to a reverse Information Element
    /// (RFC 5103, Private Enterprise Number 29305)
    pub fn is_reverse(&self) -> bool {
        self.enterprise_number == Some(registry::REVERSE_INFORMATION_ELEMENT_PEN)
    }

    /// The IANA Information Element this Field Specifier refers to.
    ///
    /// For reverse Information Elements (RFC 5103), the forward Information
    /// Element is returned. RFC 5103 Section 6.1 lets a Collecting Process
    /// *discard* the reverse counterpart of a non-reversible element; this
    /// parser keeps and decodes it instead. Returns `None` for
    /// enterprise-specific or unknown Information Elements.
    pub fn information_element(&self) -> Option<&'static InformationElement> {
        match self.enterprise_number {
            None | Some(registry::REVERSE_INFORMATION_ELEMENT_PEN) => {
                registry::lookup(self.information_element_identifier)
            }
            Some(_) => None,
        }
    }
}

/// Template Record - RFC 7011 Section 3.4.1
///
/// A Template Record Header followed by `field_count` Field Specifiers.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Template ID (> 255)      |         Field Count           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// A record with a Field Count of 0 is a Template Withdrawal
/// (RFC 7011 Section 8.1); Template ID 2 withdraws all Templates of the
/// Observation Domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TemplateRecord {
    /// Template ID, in the range 256 to 65535 (or 2 for an All Templates
    /// Withdrawal)
    pub template_id: u16,
    /// Number of fields in this Template Record
    pub field_count: u16,
    /// Field Specifiers
    pub field_specifiers: Vec<FieldSpecifier>,
}

impl TemplateRecord {
    /// Whether this record is a Template Withdrawal (RFC 7011 Section 8.1)
    pub fn is_withdrawal(&self) -> bool {
        self.field_count == 0
    }
}

/// Options Template Record - RFC 7011 Section 3.4.2.2
///
/// An Options Template Record Header followed by `field_count` Field
/// Specifiers, the first `scope_field_count` of which are Scope Fields.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Template ID (> 255)   |         Field Count           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Scope Field Count        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// A record with a Field Count of 0 is an Options Template Withdrawal
/// (RFC 7011 Section 8.1); it carries no Scope Field Count (set to 0 here).
/// Template ID 3 withdraws all Options Templates of the Observation Domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OptionsTemplateRecord {
    /// Template ID, in the range 256 to 65535 (or 3 for an All Options
    /// Templates Withdrawal)
    pub template_id: u16,
    /// Number of all fields in this Options Template Record, including the
    /// Scope Fields
    pub field_count: u16,
    /// Number of Scope Fields (MUST NOT be zero, except in a withdrawal)
    pub scope_field_count: u16,
    /// Field Specifiers (Scope Fields first)
    pub field_specifiers: Vec<FieldSpecifier>,
}

impl OptionsTemplateRecord {
    /// Whether this record is an Options Template Withdrawal
    /// (RFC 7011 Section 8.1)
    pub fn is_withdrawal(&self) -> bool {
        self.field_count == 0
    }
}

/// A decoded field of a Data Record: the Field Specifier from the Template and
/// the decoded value
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Field {
    /// Field Specifier from the Template
    pub specifier: FieldSpecifier,
    /// Decoded value
    pub value: FieldValue,
}

impl Field {
    /// The IANA Information Element of this field (forward element for
    /// reverse fields), if known
    pub fn information_element(&self) -> Option<&'static InformationElement> {
        self.specifier.information_element()
    }

    /// The IANA name of this field's Information Element, if known.
    ///
    /// Reverse Information Elements (RFC 5103) return the forward name; use
    /// [`FieldSpecifier::is_reverse`] to distinguish them.
    pub fn name(&self) -> Option<&'static str> {
        self.information_element().map(|ie| ie.name)
    }
}

/// Data Record - RFC 7011 Section 3.4.3
///
/// The Field Values of a Data Record are in the same order as the Field
/// Specifiers of the Template (or Options Template) it was decoded with.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DataRecord {
    /// Template ID used to decode this record
    pub template_id: u16,
    /// Number of leading Scope Fields (0 unless decoded with an Options
    /// Template)
    pub scope_field_count: u16,
    /// Decoded fields
    pub fields: Vec<Field>,
}

impl DataRecord {
    /// Find the first IANA (non-reverse) field by Information Element name
    pub fn get(&self, name: &str) -> Option<&FieldValue> {
        self.fields
            .iter()
            .find(|f| f.specifier.enterprise_number.is_none() && f.name() == Some(name))
            .map(|f| &f.value)
    }

    /// Find the first field by Information Element identifier and Private
    /// Enterprise Number (`None` for IANA elements)
    pub fn get_by_id(&self, id: u16, enterprise_number: Option<u32>) -> Option<&FieldValue> {
        self.fields
            .iter()
            .find(|f| {
                f.specifier.information_element_identifier == id
                    && f.specifier.enterprise_number == enterprise_number
            })
            .map(|f| &f.value)
    }

    /// The Scope Fields of a record decoded with an Options Template
    pub fn scope_fields(&self) -> &[Field] {
        let n = (self.scope_field_count as usize).min(self.fields.len());
        &self.fields[..n]
    }

    /// The non-scope fields
    pub fn non_scope_fields(&self) -> &[Field] {
        let n = (self.scope_field_count as usize).min(self.fields.len());
        &self.fields[n..]
    }
}

/// IPFIX Set - RFC 7011 Section 3.3
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Set {
    /// Template Set (Set ID 2)
    Template {
        header: SetHeader,
        records: Vec<TemplateRecord>,
    },
    /// Options Template Set (Set ID 3)
    OptionsTemplate {
        header: SetHeader,
        records: Vec<OptionsTemplateRecord>,
    },
    /// Data Set decoded with a known Template (Set ID = Template ID >= 256)
    Data {
        header: SetHeader,
        records: Vec<DataRecord>,
    },
    /// Data Set whose Template is unknown to the decoder. RFC 7011 Section 8
    /// lets the Collecting Process buffer or drop it; the raw Set content
    /// (without the Set Header) is kept so the caller can decide.
    UndecodedData { header: SetHeader, payload: Vec<u8> },
    /// Set with a reserved Set ID (0, 1 or 4-255), kept as raw content
    Reserved { header: SetHeader, payload: Vec<u8> },
}

impl Set {
    /// The Set Header
    pub fn header(&self) -> &SetHeader {
        match self {
            Set::Template { header, .. }
            | Set::OptionsTemplate { header, .. }
            | Set::Data { header, .. }
            | Set::UndecodedData { header, .. }
            | Set::Reserved { header, .. } => header,
        }
    }
}

/// IPFIX Message - RFC 7011 Section 3
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Message {
    /// Message Header
    pub header: MessageHeader,
    /// Sets, in the order they appear in the Message
    pub sets: Vec<Set>,
}

impl Message {
    /// Iterate over all decoded Data Records of the Message
    pub fn data_records(&self) -> impl Iterator<Item = &DataRecord> {
        self.sets.iter().flat_map(|set| match set {
            Set::Data { records, .. } => records.as_slice(),
            _ => &[],
        })
    }
}
