//! Enterprise-specific Information Element definitions
//!
//! The type of an enterprise-specific Information Element is not in the IANA
//! registry. It can come from two sources, see [`ElementSource`]:
//!
//! - a definition registered by the caller (e.g. from vendor documentation),
//!   with [`Decoder::register_enterprise_element`](crate::Decoder::register_enterprise_element);
//! - an Information Element type record sent by the Exporter
//!   ([RFC 5610](https://www.rfc-editor.org/rfc/rfc5610)).

use crate::registry::{DataType, DataTypeSemantics};

/// Where an enterprise-specific Information Element definition comes from
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ElementSource {
    /// Registered by the caller. This is the Collecting Process's "own
    /// internal definition": it always takes precedence over type records
    /// (RFC 5610 Section 3.9).
    Registered,
    /// Learned from an Information Element type record sent by the Exporter
    /// (RFC 5610), scoped to the Transport Session and Observation Domain.
    TypeRecord,
}

/// Type information of an enterprise-specific Information Element
/// (RFC 5610 Section 3)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EnterpriseElement {
    /// Private Enterprise Number (`privateEnterpriseNumber`, 346)
    pub enterprise_number: u32,
    /// Information Element identifier (`informationElementId`, 303)
    pub id: u16,
    /// Name (`informationElementName`, 341)
    pub name: Option<String>,
    /// Abstract data type (`informationElementDataType`, 339)
    pub data_type: DataType,
    /// Data type semantics (`informationElementSemantics`, 344)
    pub semantics: Option<DataTypeSemantics>,
    /// Units, as a value of the IANA "IPFIX Information Element Units"
    /// registry (`informationElementUnits`, 345)
    pub units: Option<u16>,
    /// Inclusive low end of the range of acceptable values
    /// (`informationElementRangeBegin`, 342)
    pub range_begin: Option<u64>,
    /// Inclusive high end of the range of acceptable values
    /// (`informationElementRangeEnd`, 343)
    pub range_end: Option<u64>,
    /// Human-readable description (`informationElementDescription`, 340)
    pub description: Option<String>,
    /// Where the definition comes from
    pub source: ElementSource,
}

impl EnterpriseElement {
    /// A caller-registered definition with a name and a data type
    pub fn new(enterprise_number: u32, id: u16, name: &str, data_type: DataType) -> Self {
        Self {
            enterprise_number,
            id,
            name: Some(name.to_string()),
            data_type,
            semantics: None,
            units: None,
            range_begin: None,
            range_end: None,
            description: None,
            source: ElementSource::Registered,
        }
    }

    /// Set the data type semantics
    pub fn with_semantics(mut self, semantics: DataTypeSemantics) -> Self {
        self.semantics = Some(semantics);
        self
    }

    /// Whether the data type and semantics combination is valid
    /// (RFC 5610 Section 3.10). Invalid combinations MUST be ignored.
    ///
    /// RFC 5610 predates the structured data types (RFC 6313) and
    /// `unsigned256` (RFC 9740): lists accept the `list` semantics, and
    /// `unsigned256` follows the other unsigned types.
    pub fn has_valid_semantics(&self) -> bool {
        let Some(semantics) = self.semantics else {
            return true;
        };
        use DataType::*;
        use DataTypeSemantics as S;
        match self.data_type {
            Unsigned8 | Unsigned16 | Unsigned32 | Unsigned64 | Unsigned256 => true,
            Signed8 | Signed16 | Signed32 | Signed64 => semantics != S::Flags,
            Float32 | Float64 => !matches!(semantics, S::Identifier | S::Flags),
            BasicList | SubTemplateList | SubTemplateMultiList => {
                matches!(semantics, S::Default | S::List)
            }
            _ => semantics == S::Default,
        }
    }
}
