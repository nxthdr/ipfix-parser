//! Tests for serde serialization/deserialization
//!
//! These tests verify that all IPFIX data structures can be properly
//! serialized and deserialized when the serde feature is enabled.

#![cfg(feature = "serde")]

use ipfix_parser::models::*;
use ipfix_parser::parse_messages;

fn roundtrip<T>(value: &T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let json = serde_json::to_string(value).unwrap();
    let deserialized: T = serde_json::from_str(&json).unwrap();
    assert_eq!(value, &deserialized);
}

#[test]
fn test_messages_serde() {
    let data = std::fs::read("tests/data/ipfix.bin").expect("Failed to read ipfix.bin");
    let messages = parse_messages(&data).unwrap();
    for message in &messages {
        roundtrip(message);
    }
}

#[test]
fn test_field_values_serde() {
    let values = vec![
        FieldValue::OctetArray(vec![1, 2, 3]),
        FieldValue::Unsigned(u64::MAX),
        FieldValue::Unsigned256([0xAB; 32]),
        FieldValue::Signed(-1),
        FieldValue::Float32(1.5),
        FieldValue::Float64(-2.25),
        FieldValue::Boolean(true),
        FieldValue::MacAddress(MacAddress::new([0, 1, 2, 3, 4, 5])),
        FieldValue::String("eth0".to_string()),
        FieldValue::DateTimeSeconds(1),
        FieldValue::DateTimeMilliseconds(2),
        FieldValue::DateTimeMicroseconds(NtpTimestamp {
            seconds: 3,
            fraction: 4,
        }),
        FieldValue::DateTimeNanoseconds(NtpTimestamp {
            seconds: 5,
            fraction: 6,
        }),
        FieldValue::Ipv4Address("192.0.2.1".parse().unwrap()),
        FieldValue::Ipv6Address("2001:db8::1".parse().unwrap()),
        FieldValue::Raw(vec![0xFF]),
    ];
    for value in &values {
        roundtrip(value);
    }
}

#[test]
fn test_structured_data_serde() {
    let record = DataRecord {
        template_id: 300,
        scope_field_count: 0,
        fields: vec![Field {
            specifier: FieldSpecifier {
                information_element_identifier: 4,
                field_length: 1,
                enterprise_number: None,
            },
            value: FieldValue::Unsigned(6),
        }],
    };
    roundtrip(&FieldValue::BasicList(BasicList {
        semantic: ListSemantic::AllOf,
        field_id: 10,
        element_length: 4,
        enterprise_number: Some(9),
        basic_list_content: vec![FieldValue::Unsigned(1)],
    }));
    roundtrip(&FieldValue::SubTemplateList(SubTemplateList {
        semantic: ListSemantic::Unassigned(0x42),
        template_id: 300,
        sub_template_list_content: vec![record.clone()],
    }));
    roundtrip(&FieldValue::SubTemplateMultiList(SubTemplateMultiList {
        semantic: ListSemantic::Undefined,
        entries: vec![SubTemplateMultiListEntry {
            template_id: 300,
            data_records_length: 5,
            data_records: vec![record],
        }],
    }));
}

#[test]
fn test_enterprise_element_serde() {
    use ipfix_parser::registry::{DataType, DataTypeSemantics};
    let mut element = EnterpriseElement::new(9, 100, "vendorOctets", DataType::Unsigned64)
        .with_semantics(DataTypeSemantics::DeltaCounter);
    element.units = Some(1);
    element.source = ElementSource::TypeRecord;
    roundtrip(&element);
}
