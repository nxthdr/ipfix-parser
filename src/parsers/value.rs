//! Data Record and field value decoding
//!
//! Encodings follow RFC 7011 Section 6 (data types), Section 7
//! (variable-length Information Elements) and RFC 6313 Section 4.5
//! (structured data).
//!
//! Framing errors (a Data Record running past the end of its Set) fail the
//! Message. A value that does not match its Information Element's type is not
//! a framing error: it is kept as [`FieldValue::Raw`].
//!
//! # Known Specification Errata
//!
//! - **RFC 7011 Errata 7875 (Section 6.2):** reduced-size signed integers drop
//!   leading ones for negative values, so they are sign-extended.
//! - **RFC 6313 Errata 3232 (Section 4.5.3):** the Data Records Length of a
//!   subTemplateMultiList entry includes the Template ID and Length fields, so
//!   a value below 4 is invalid.

use super::decoder::{Template, TemplateCache};
use super::error::Result;
use super::Cursor;
use crate::models::*;
use crate::registry::DataType;
use std::net::{Ipv4Addr, Ipv6Addr};

pub(crate) struct DecodeContext<'a> {
    pub(crate) templates: &'a TemplateCache,
    pub(crate) observation_domain_id: u32,
    pub(crate) max_depth: usize,
}

impl DecodeContext<'_> {
    fn template(&self, template_id: u16) -> Option<&Template> {
        self.templates
            .get(&(self.observation_domain_id, template_id))
    }
}

/// Decode one Data Record (RFC 7011 Section 3.4.3) with its Template
pub(crate) fn decode_record(
    ctx: &DecodeContext,
    template_id: u16,
    template: &Template,
    cursor: &mut Cursor,
    depth: usize,
) -> Result<DataRecord> {
    let mut fields = Vec::with_capacity(template.field_specifiers.len());
    for specifier in &template.field_specifiers {
        let bytes = read_field(cursor, specifier)?;
        fields.push(Field {
            specifier: *specifier,
            value: decode_value(ctx, specifier, bytes, depth),
        });
    }
    Ok(DataRecord {
        template_id,
        scope_field_count: template.scope_field_count,
        fields,
    })
}

/// Read the encoded octets of one field (fixed or variable-length)
fn read_field<'a>(cursor: &mut Cursor<'a>, specifier: &FieldSpecifier) -> Result<&'a [u8]> {
    let length = if specifier.is_variable_length() {
        cursor.read_variable_length("variable-length field")?
    } else {
        specifier.field_length as usize
    };
    cursor.read_bytes(length, "field value")
}

/// Decode a field value according to its Information Element's data type
pub(crate) fn decode_value(
    ctx: &DecodeContext,
    specifier: &FieldSpecifier,
    bytes: &[u8],
    depth: usize,
) -> FieldValue {
    let raw = || FieldValue::Raw(bytes.to_vec());
    let Some(data_type) = specifier.information_element().map(|ie| ie.data_type) else {
        return raw();
    };
    let len = bytes.len();

    match data_type {
        DataType::OctetArray => FieldValue::OctetArray(bytes.to_vec()),
        DataType::Unsigned8
        | DataType::Unsigned16
        | DataType::Unsigned32
        | DataType::Unsigned64 => match fits_reduced(data_type, len) {
            true => FieldValue::Unsigned(be_uint(bytes)),
            false => raw(),
        },
        DataType::Signed8 | DataType::Signed16 | DataType::Signed32 | DataType::Signed64 => {
            match fits_reduced(data_type, len) {
                true => {
                    let shift = 64 - 8 * len as u32;
                    FieldValue::Signed(((be_uint(bytes) << shift) as i64) >> shift)
                }
                false => raw(),
            }
        }
        DataType::Unsigned256 if (1..=32).contains(&len) => {
            let mut value = [0u8; 32];
            value[32 - len..].copy_from_slice(bytes);
            FieldValue::Unsigned256(value)
        }
        DataType::Float32 if len == 4 => FieldValue::Float32(f32::from_bits(be_uint(bytes) as u32)),
        DataType::Float64 if len == 8 => FieldValue::Float64(f64::from_bits(be_uint(bytes))),
        // Reduced-size encoding of float64 as float32 (RFC 7011 Section 6.2)
        DataType::Float64 if len == 4 => {
            FieldValue::Float64(f32::from_bits(be_uint(bytes) as u32) as f64)
        }
        DataType::Boolean if bytes == [1] => FieldValue::Boolean(true),
        DataType::Boolean if bytes == [2] => FieldValue::Boolean(false),
        DataType::MacAddress if len == 6 => {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(bytes);
            FieldValue::MacAddress(MacAddress(mac))
        }
        DataType::String => match std::str::from_utf8(bytes) {
            Ok(s) => FieldValue::String(s.to_string()),
            Err(_) => raw(),
        },
        DataType::DateTimeSeconds if len == 4 => FieldValue::DateTimeSeconds(be_uint(bytes) as u32),
        DataType::DateTimeMilliseconds if len == 8 => {
            FieldValue::DateTimeMilliseconds(be_uint(bytes))
        }
        DataType::DateTimeMicroseconds if len == 8 => FieldValue::DateTimeMicroseconds(ntp(bytes)),
        DataType::DateTimeNanoseconds if len == 8 => FieldValue::DateTimeNanoseconds(ntp(bytes)),
        DataType::Ipv4Address if len == 4 => {
            FieldValue::Ipv4Address(Ipv4Addr::from(be_uint(bytes) as u32))
        }
        DataType::Ipv6Address if len == 16 => {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(bytes);
            FieldValue::Ipv6Address(Ipv6Addr::from(addr))
        }
        DataType::BasicList if depth < ctx.max_depth => decode_basic_list(ctx, bytes, depth)
            .map(FieldValue::BasicList)
            .unwrap_or_else(raw),
        DataType::SubTemplateList if depth < ctx.max_depth => {
            decode_sub_template_list(ctx, bytes, depth)
                .map(FieldValue::SubTemplateList)
                .unwrap_or_else(raw)
        }
        DataType::SubTemplateMultiList if depth < ctx.max_depth => {
            decode_sub_template_multi_list(ctx, bytes, depth)
                .map(FieldValue::SubTemplateMultiList)
                .unwrap_or_else(raw)
        }
        _ => raw(),
    }
}

/// Whether an integer of `data_type` can be encoded in `len` octets
/// (reduced-size encoding, RFC 7011 Section 6.2)
fn fits_reduced(data_type: DataType, len: usize) -> bool {
    let native = data_type.default_length().unwrap_or(0) as usize;
    (1..=native).contains(&len)
}

/// Big-endian unsigned integer of at most 8 octets
fn be_uint(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64)
}

fn ntp(bytes: &[u8]) -> NtpTimestamp {
    NtpTimestamp {
        seconds: be_uint(&bytes[..4]) as u32,
        fraction: be_uint(&bytes[4..8]) as u32,
    }
}

/// Decode a basicList (RFC 6313 Section 4.5.1)
fn decode_basic_list(ctx: &DecodeContext, bytes: &[u8], depth: usize) -> Option<BasicList> {
    let mut cursor = Cursor::new(bytes);
    let semantic = ListSemantic::from(cursor.read_u8("basicList").ok()?);
    let (field_id, enterprise) = cursor.read_field_id("basicList").ok()?;
    let element_length = cursor.read_u16("basicList").ok()?;
    let enterprise_number = match enterprise {
        true => Some(cursor.read_u32("basicList").ok()?),
        false => None,
    };
    // A zero-length element would never consume the content
    if element_length == 0 {
        return None;
    }

    let element = FieldSpecifier {
        information_element_identifier: field_id,
        field_length: element_length,
        enterprise_number,
    };
    let mut basic_list_content = Vec::new();
    while !cursor.is_empty() {
        let value = read_field(&mut cursor, &element).ok()?;
        basic_list_content.push(decode_value(ctx, &element, value, depth + 1));
    }

    Some(BasicList {
        semantic,
        field_id,
        element_length,
        enterprise_number,
        basic_list_content,
    })
}

/// Decode Data Records until the content is exhausted (no padding is allowed
/// inside structured data)
fn decode_records(
    ctx: &DecodeContext,
    template_id: u16,
    content: &[u8],
    depth: usize,
) -> Option<Vec<DataRecord>> {
    let template = ctx.template(template_id)?;
    let mut cursor = Cursor::new(content);
    let mut records = Vec::new();
    while !cursor.is_empty() {
        records.push(decode_record(ctx, template_id, template, &mut cursor, depth + 1).ok()?);
    }
    Some(records)
}

/// Decode a subTemplateList (RFC 6313 Section 4.5.2)
fn decode_sub_template_list(
    ctx: &DecodeContext,
    bytes: &[u8],
    depth: usize,
) -> Option<SubTemplateList> {
    let mut cursor = Cursor::new(bytes);
    let semantic = ListSemantic::from(cursor.read_u8("subTemplateList").ok()?);
    let template_id = cursor.read_u16("subTemplateList").ok()?;
    let sub_template_list_content = decode_records(ctx, template_id, cursor.read_rest(), depth)?;
    Some(SubTemplateList {
        semantic,
        template_id,
        sub_template_list_content,
    })
}

/// Decode a subTemplateMultiList (RFC 6313 Section 4.5.3)
fn decode_sub_template_multi_list(
    ctx: &DecodeContext,
    bytes: &[u8],
    depth: usize,
) -> Option<SubTemplateMultiList> {
    let mut cursor = Cursor::new(bytes);
    let semantic = ListSemantic::from(cursor.read_u8("subTemplateMultiList").ok()?);
    let mut entries = Vec::new();
    while !cursor.is_empty() {
        let template_id = cursor.read_u16("subTemplateMultiList").ok()?;
        let data_records_length = cursor.read_u16("subTemplateMultiList").ok()?;
        // The length includes the Template ID and Length fields (Errata 3232)
        let content_length = (data_records_length as usize).checked_sub(4)?;
        let content = cursor
            .read_bytes(content_length, "subTemplateMultiList")
            .ok()?;
        entries.push(SubTemplateMultiListEntry {
            template_id,
            data_records_length,
            data_records: decode_records(ctx, template_id, content, depth)?,
        });
    }
    Some(SubTemplateMultiList { semantic, entries })
}
