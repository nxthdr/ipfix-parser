//! Structured data types - RFC 6313

use super::helpers::{varlen, MessageBuilder, Spec, VARIABLE};
use ipfix_parser::models::{BasicList, ListSemantic, SubTemplateList};
use ipfix_parser::{parse_message, Decoder, DecoderConfig, FieldValue};
use std::net::Ipv4Addr;

const BASIC_LIST: u16 = 291;
const SUB_TEMPLATE_LIST: u16 = 292;
const SUB_TEMPLATE_MULTI_LIST: u16 = 293;

/// Decode a single variable-length structured value, with extra Templates
/// defined before the record's Template (256)
fn decode_structured(extra_templates: &[(u16, &[Spec])], ie: u16, content: &[u8]) -> FieldValue {
    let mut builder = MessageBuilder::new();
    for (id, specs) in extra_templates {
        builder = builder.template(*id, specs);
    }
    let data = builder
        .template(256, &[(ie, VARIABLE, None)])
        .data(256, &varlen(content))
        .build();
    let message = parse_message(&data).expect("Failed to parse");
    let value = message.data_records().next().unwrap().fields[0]
        .value
        .clone();
    value
}

fn basic_list_header(semantic: u8, field_id: u16, element_length: u16) -> Vec<u8> {
    let mut out = vec![semantic];
    out.extend_from_slice(&field_id.to_be_bytes());
    out.extend_from_slice(&element_length.to_be_bytes());
    out
}

#[test]
fn test_list_semantic_values() {
    for value in [0x00, 0x01, 0x02, 0x03, 0x04, 0xFF, 0x42] {
        assert_eq!(ListSemantic::from(value).value(), value);
    }
    assert_eq!(ListSemantic::from(0x03), ListSemantic::AllOf);
    assert_eq!(ListSemantic::from(0x42), ListSemantic::Unassigned(0x42));
}

#[test]
fn test_basic_list_fixed_length() {
    // allOf list of three ingressInterface (10) values
    let mut content = basic_list_header(0x03, 10, 4);
    for i in [1u32, 2, 3] {
        content.extend_from_slice(&i.to_be_bytes());
    }
    assert_eq!(
        decode_structured(&[], BASIC_LIST, &content),
        FieldValue::BasicList(BasicList {
            semantic: ListSemantic::AllOf,
            field_id: 10,
            element_length: 4,
            enterprise_number: None,
            basic_list_content: vec![
                FieldValue::Unsigned(1),
                FieldValue::Unsigned(2),
                FieldValue::Unsigned(3),
            ],
        })
    );
}

#[test]
fn test_basic_list_variable_length_elements() {
    // interfaceName (82) elements, each with its own length prefix
    let mut content = basic_list_header(0x04, 82, VARIABLE);
    content.extend_from_slice(&varlen(b"eth0"));
    content.extend_from_slice(&varlen(b"eth1"));
    let FieldValue::BasicList(list) = decode_structured(&[], BASIC_LIST, &content) else {
        panic!("Expected a basicList");
    };
    assert_eq!(list.semantic, ListSemantic::Ordered);
    assert_eq!(
        list.basic_list_content,
        vec![
            FieldValue::String("eth0".to_string()),
            FieldValue::String("eth1".to_string()),
        ]
    );
}

#[test]
fn test_basic_list_with_enterprise_number() {
    // RFC 6313 Figure 2: the Enterprise Number follows the Element Length
    let mut content = basic_list_header(0xFF, 5 | 0x8000, 2);
    content.extend_from_slice(&9u32.to_be_bytes());
    content.extend_from_slice(&[0xAA, 0xBB]);
    let FieldValue::BasicList(list) = decode_structured(&[], BASIC_LIST, &content) else {
        panic!("Expected a basicList");
    };
    assert_eq!(list.field_id, 5);
    assert_eq!(list.enterprise_number, Some(9));
    assert_eq!(
        list.basic_list_content,
        vec![FieldValue::Raw(vec![0xAA, 0xBB])]
    );
}

#[test]
fn test_basic_list_empty() {
    // A zero-element list still carries its header
    let content = basic_list_header(0x00, 10, 4);
    let FieldValue::BasicList(list) = decode_structured(&[], BASIC_LIST, &content) else {
        panic!("Expected a basicList");
    };
    assert!(list.basic_list_content.is_empty());
}

#[test]
fn test_basic_list_zero_element_length_is_raw() {
    // A zero Element Length would never consume the content
    let mut content = basic_list_header(0x03, 10, 0);
    content.extend_from_slice(&[1, 2, 3, 4]);
    assert_eq!(
        decode_structured(&[], BASIC_LIST, &content),
        FieldValue::Raw(content)
    );
}

#[test]
fn test_basic_list_truncated_element_is_raw() {
    let mut content = basic_list_header(0x03, 10, 4);
    content.extend_from_slice(&[0, 0, 0, 1, 0, 0]);
    assert_eq!(
        decode_structured(&[], BASIC_LIST, &content),
        FieldValue::Raw(content)
    );
}

#[test]
fn test_sub_template_list() {
    // Two records of Template 300 (sourceIPv4Address, sourceTransportPort)
    let inner: &[Spec] = &[(8, 4, None), (7, 2, None)];
    let mut content = vec![0x03];
    content.extend_from_slice(&300u16.to_be_bytes());
    content.extend_from_slice(&[10, 0, 0, 1, 0x00, 0x50]);
    content.extend_from_slice(&[10, 0, 0, 2, 0x01, 0xBB]);

    let FieldValue::SubTemplateList(SubTemplateList {
        semantic,
        template_id,
        sub_template_list_content: records,
    }) = decode_structured(&[(300, inner)], SUB_TEMPLATE_LIST, &content)
    else {
        panic!("Expected a subTemplateList");
    };
    assert_eq!(semantic, ListSemantic::AllOf);
    assert_eq!(template_id, 300);
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[1].get("sourceIPv4Address"),
        Some(&FieldValue::Ipv4Address(Ipv4Addr::new(10, 0, 0, 2)))
    );
    assert_eq!(
        records[1].get("sourceTransportPort"),
        Some(&FieldValue::Unsigned(443))
    );
}

#[test]
fn test_sub_template_list_unknown_template_is_raw() {
    let mut content = vec![0x03];
    content.extend_from_slice(&999u16.to_be_bytes());
    content.extend_from_slice(&[1, 2, 3, 4]);
    assert_eq!(
        decode_structured(&[], SUB_TEMPLATE_LIST, &content),
        FieldValue::Raw(content)
    );
}

#[test]
fn test_sub_template_multi_list() {
    let first: &[Spec] = &[(4, 1, None)]; // protocolIdentifier
    let second: &[Spec] = &[(7, 2, None)]; // sourceTransportPort
    let mut content = vec![0x02];
    // Template 300: two records
    content.extend_from_slice(&300u16.to_be_bytes());
    content.extend_from_slice(&6u16.to_be_bytes());
    content.extend_from_slice(&[6, 17]);
    // Template 301: one record
    content.extend_from_slice(&301u16.to_be_bytes());
    content.extend_from_slice(&6u16.to_be_bytes());
    content.extend_from_slice(&[0x00, 0x35]);

    let FieldValue::SubTemplateMultiList(list) = decode_structured(
        &[(300, first), (301, second)],
        SUB_TEMPLATE_MULTI_LIST,
        &content,
    ) else {
        panic!("Expected a subTemplateMultiList");
    };
    assert_eq!(list.semantic, ListSemantic::OneOrMoreOf);
    assert_eq!(list.entries.len(), 2);
    assert_eq!(list.entries[0].template_id, 300);
    assert_eq!(list.entries[0].data_records.len(), 2);
    assert_eq!(
        list.entries[1].data_records[0].get("sourceTransportPort"),
        Some(&FieldValue::Unsigned(53))
    );
}

#[test]
fn test_sub_template_multi_list_empty_entry() {
    // RFC 6313 Errata 3232: an empty entry has a Data Records Length of 4
    let first: &[Spec] = &[(4, 1, None)];
    let mut content = vec![0x03];
    content.extend_from_slice(&300u16.to_be_bytes());
    content.extend_from_slice(&4u16.to_be_bytes());
    let FieldValue::SubTemplateMultiList(list) =
        decode_structured(&[(300, first)], SUB_TEMPLATE_MULTI_LIST, &content)
    else {
        panic!("Expected a subTemplateMultiList");
    };
    assert_eq!(list.entries[0].data_records_length, 4);
    assert!(list.entries[0].data_records.is_empty());
}

#[test]
fn test_sub_template_multi_list_length_below_four_is_raw() {
    // RFC 6313 Errata 3232: a Data Records Length < 4 is invalid
    let first: &[Spec] = &[(4, 1, None)];
    let mut content = vec![0x03];
    content.extend_from_slice(&300u16.to_be_bytes());
    content.extend_from_slice(&0u16.to_be_bytes());
    assert_eq!(
        decode_structured(&[(300, first)], SUB_TEMPLATE_MULTI_LIST, &content),
        FieldValue::Raw(content)
    );
}

#[test]
fn test_nested_lists_beyond_max_depth_are_raw() {
    // Template 300 holds a subTemplateList of Template 301 records, which hold a
    // basicList of protocolIdentifier
    let t300: &[Spec] = &[(SUB_TEMPLATE_LIST, VARIABLE, None)];
    let t301: &[Spec] = &[(BASIC_LIST, VARIABLE, None)];
    let mut basic = basic_list_header(0x03, 4, 1);
    basic.push(6);
    let mut inner = vec![0x03];
    inner.extend_from_slice(&301u16.to_be_bytes());
    inner.extend_from_slice(&varlen(&basic));
    let mut outer = vec![0x03];
    outer.extend_from_slice(&300u16.to_be_bytes());
    outer.extend_from_slice(&varlen(&inner));

    let data = MessageBuilder::new()
        .template(300, t300)
        .template(301, t301)
        .template(256, &[(SUB_TEMPLATE_LIST, VARIABLE, None)])
        .data(256, &varlen(&outer))
        .build();

    // Default depth: fully decoded
    let message = parse_message(&data).unwrap();
    let FieldValue::SubTemplateList(l1) = &message.data_records().next().unwrap().fields[0].value
    else {
        panic!("Expected a subTemplateList");
    };
    let FieldValue::SubTemplateList(l2) = &l1.sub_template_list_content[0].fields[0].value else {
        panic!("Expected a nested subTemplateList");
    };
    assert!(matches!(
        l2.sub_template_list_content[0].fields[0].value,
        FieldValue::BasicList(_)
    ));

    // max_list_depth = 2: the innermost basicList is kept raw
    let mut decoder = Decoder::with_config(DecoderConfig {
        max_list_depth: 2,
        ..DecoderConfig::default()
    });
    let message = decoder.decode(&data).unwrap();
    let FieldValue::SubTemplateList(l1) = &message.data_records().next().unwrap().fields[0].value
    else {
        panic!("Expected a subTemplateList");
    };
    let FieldValue::SubTemplateList(l2) = &l1.sub_template_list_content[0].fields[0].value else {
        panic!("Expected a nested subTemplateList");
    };
    assert_eq!(
        l2.sub_template_list_content[0].fields[0].value,
        FieldValue::Raw(basic)
    );
}
