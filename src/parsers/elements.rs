//! Enterprise-specific Information Element types - RFC 5610
//!
//! The decoder keeps a table of enterprise-specific Information Element
//! definitions, used to decode fields that the IANA registry does not
//! describe. Definitions come from two sources:
//!
//! 1. **Registered** by the caller ([`Decoder::register_enterprise_element`]).
//!    They are the Collecting Process's "own internal definition", which an
//!    Information Element type record MUST NOT replace (RFC 5610 Section 3.9).
//! 2. **Learned** from Information Element type records: Data Records of an
//!    Options Template whose Scope Fields include `informationElementId` (303)
//!    and `privateEnterpriseNumber` (346). They are scoped to the Transport
//!    Session (the [`Decoder`]) and the Observation Domain.
//!
//! RFC 5610 rules applied to type records (Sections 3.9, 3.10 and 4):
//!
//! - they never replace a registered definition, nor an IANA Information
//!   Element known to the registry;
//! - once a type record is received for an Information Element, a different
//!   one marks the element as conflicting, and it is then ignored (kept as
//!   [`FieldValue::Raw`]);
//! - invalid data type / semantics combinations are ignored;
//! - names and descriptions containing a NUL character are ignored;
//! - reverse Information Elements (RFC 5103) cannot be described, as the
//!   Reverse PEN only allocates counterparts of IANA elements.
//!
//! The learned table is bounded by [`DecoderConfig::max_enterprise_elements`]:
//! further type records are ignored, as they only carry metadata.
//!
//! [`Decoder`]: super::Decoder
//! [`Decoder::register_enterprise_element`]: super::Decoder::register_enterprise_element
//! [`DecoderConfig::max_enterprise_elements`]: super::DecoderConfig::max_enterprise_elements
//! [`FieldValue::Raw`]: crate::FieldValue::Raw

use super::error::{ParseError, Result};
use crate::models::*;
use crate::registry::{self, DataType, DataTypeSemantics, REVERSE_INFORMATION_ELEMENT_PEN};
use std::collections::HashMap;

/// `informationElementId` (RFC 5477)
pub(crate) const INFORMATION_ELEMENT_ID: u16 = 303;
/// `privateEnterpriseNumber` (RFC 5610 Section 3.8)
pub(crate) const PRIVATE_ENTERPRISE_NUMBER: u16 = 346;
/// `informationElementDataType` (RFC 5610 Section 3.1)
pub(crate) const INFORMATION_ELEMENT_DATA_TYPE: u16 = 339;
/// `informationElementDescription` (RFC 5610 Section 3.2)
pub(crate) const INFORMATION_ELEMENT_DESCRIPTION: u16 = 340;
/// `informationElementName` (RFC 5610 Section 3.3)
pub(crate) const INFORMATION_ELEMENT_NAME: u16 = 341;
/// `informationElementRangeBegin` (RFC 5610 Section 3.4)
pub(crate) const INFORMATION_ELEMENT_RANGE_BEGIN: u16 = 342;
/// `informationElementRangeEnd` (RFC 5610 Section 3.5)
pub(crate) const INFORMATION_ELEMENT_RANGE_END: u16 = 343;
/// `informationElementSemantics` (RFC 5610 Section 3.6)
pub(crate) const INFORMATION_ELEMENT_SEMANTICS: u16 = 344;
/// `informationElementUnits` (RFC 5610 Section 3.7)
pub(crate) const INFORMATION_ELEMENT_UNITS: u16 = 345;

/// A learned type record, or the marker of conflicting type records
#[derive(Debug, Clone, PartialEq, Eq)]
enum Learned {
    Element(EnterpriseElement),
    Conflicting,
}

/// Enterprise-specific Information Element definitions of a Decoder
#[derive(Debug, Clone, Default)]
pub(crate) struct ElementTable {
    /// Registered by the caller, keyed by (PEN, ID)
    registered: HashMap<(u32, u16), EnterpriseElement>,
    /// Learned from type records, keyed by (Observation Domain, PEN, ID)
    learned: HashMap<(u32, u32, u16), Learned>,
}

impl ElementTable {
    pub(crate) fn register(&mut self, mut element: EnterpriseElement) -> Result<()> {
        if element.enterprise_number == REVERSE_INFORMATION_ELEMENT_PEN {
            return Err(ParseError::InvalidData(
                "Reverse Information Elements (PEN 29305) cannot be registered".to_string(),
            ));
        }
        if element.enterprise_number == 0 && registry::lookup(element.id).is_some() {
            return Err(ParseError::InvalidData(format!(
                "Information Element {} is already defined by IANA",
                element.id
            )));
        }
        if element.id > 0x7FFF {
            return Err(ParseError::InvalidData(format!(
                "Information Element identifier {} exceeds 15 bits",
                element.id
            )));
        }
        element.source = ElementSource::Registered;
        self.registered
            .insert((element.enterprise_number, element.id), element);
        Ok(())
    }

    /// The definition used for an enterprise-specific (or unknown IANA)
    /// Information Element: registered first, then learned
    pub(crate) fn get(&self, domain: u32, pen: u32, id: u16) -> Option<&EnterpriseElement> {
        self.registered
            .get(&(pen, id))
            .or_else(|| match self.learned.get(&(domain, pen, id)) {
                Some(Learned::Element(element)) => Some(element),
                _ => None,
            })
    }

    /// The data type used to decode a field
    pub(crate) fn data_type(&self, domain: u32, specifier: &FieldSpecifier) -> Option<DataType> {
        let id = specifier.information_element_identifier;
        match specifier.enterprise_number {
            // IANA elements (and their reverse counterparts): the registry, then
            // definitions of elements newer than the registry
            None | Some(REVERSE_INFORMATION_ELEMENT_PEN) => registry::lookup(id)
                .map(|ie| ie.data_type)
                .or_else(|| self.get(domain, 0, id).map(|e| e.data_type)),
            Some(pen) => self.get(domain, pen, id).map(|e| e.data_type),
        }
    }

    pub(crate) fn learned_count(&self) -> usize {
        self.learned
            .values()
            .filter(|l| matches!(l, Learned::Element(_)))
            .count()
    }

    pub(crate) fn clear_learned(&mut self) {
        self.learned.clear();
    }

    pub(crate) fn remove_domain(&mut self, domain: u32) {
        self.learned.retain(|(d, _, _), _| *d != domain);
    }

    /// Learn from a Data Record if it is an Information Element type record
    pub(crate) fn learn(&mut self, domain: u32, record: &DataRecord, max_learned: usize) {
        let Some(element) = parse_type_record(record) else {
            return;
        };
        let (pen, id) = (element.enterprise_number, element.id);
        // Never replace the Collecting Process's own definitions
        if pen == REVERSE_INFORMATION_ELEMENT_PEN
            || (pen == 0 && registry::lookup(id).is_some())
            || self.registered.contains_key(&(pen, id))
        {
            return;
        }

        let key = (domain, pen, id);
        match self.learned.get_mut(&key) {
            // Subsequent type records MUST be identical; conflicting
            // information makes the element ignored
            Some(learned @ Learned::Element(_)) => {
                if *learned != Learned::Element(element) {
                    *learned = Learned::Conflicting;
                }
            }
            Some(Learned::Conflicting) => {}
            None => {
                if self.learned.len() < max_learned {
                    self.learned.insert(key, Learned::Element(element));
                }
            }
        }
    }
}

/// The IANA (non-enterprise) field with this identifier
fn iana_field(fields: &[Field], id: u16) -> Option<&FieldValue> {
    fields
        .iter()
        .find(|f| {
            f.specifier.enterprise_number.is_none()
                && f.specifier.information_element_identifier == id
        })
        .map(|f| &f.value)
}

fn unsigned(fields: &[Field], id: u16) -> Option<u64> {
    match iana_field(fields, id) {
        Some(FieldValue::Unsigned(v)) => Some(*v),
        _ => None,
    }
}

/// A name or description, ignored if it contains a NUL character
/// (RFC 5610 Section 4)
fn text(fields: &[Field], id: u16) -> Option<String> {
    match iana_field(fields, id) {
        Some(FieldValue::String(s)) if !s.contains('\0') => Some(s.clone()),
        _ => None,
    }
}

/// Parse an Information Element type record (RFC 5610 Section 3.9), or
/// `None` if the record is not a valid type record
fn parse_type_record(record: &DataRecord) -> Option<EnterpriseElement> {
    // informationElementId and privateEnterpriseNumber MUST be Scope Fields
    let scope = record.scope_fields();
    let id = unsigned(scope, INFORMATION_ELEMENT_ID)?;
    let pen = unsigned(scope, PRIVATE_ENTERPRISE_NUMBER)?;
    let id = u16::try_from(id).ok().filter(|id| *id <= 0x7FFF)?;
    let pen = u32::try_from(pen).ok()?;

    let fields = &record.fields;
    let data_type =
        DataType::from_value(u8::try_from(unsigned(fields, INFORMATION_ELEMENT_DATA_TYPE)?).ok()?)?;
    let semantics = match unsigned(fields, INFORMATION_ELEMENT_SEMANTICS) {
        Some(value) => Some(DataTypeSemantics::from_value(u8::try_from(value).ok()?)?),
        None => None,
    };

    let element = EnterpriseElement {
        enterprise_number: pen,
        id,
        name: text(fields, INFORMATION_ELEMENT_NAME),
        data_type,
        semantics,
        units: unsigned(fields, INFORMATION_ELEMENT_UNITS).and_then(|u| u16::try_from(u).ok()),
        range_begin: unsigned(fields, INFORMATION_ELEMENT_RANGE_BEGIN),
        range_end: unsigned(fields, INFORMATION_ELEMENT_RANGE_END),
        description: text(fields, INFORMATION_ELEMENT_DESCRIPTION),
        source: ElementSource::TypeRecord,
    };
    // Invalid data type / semantics combinations MUST be ignored
    element.has_valid_semantics().then_some(element)
}
