//! Enterprise-specific Information Elements: caller-registered definitions
//! and Information Element type records (RFC 5610)

use super::helpers::{varlen, MessageBuilder, Spec, VARIABLE};
use ipfix_parser::models::{ElementSource, EnterpriseElement};
use ipfix_parser::registry::{lookup, DataType, DataTypeSemantics};
use ipfix_parser::{Decoder, DecoderConfig, FieldValue, Set};
use std::net::Ipv4Addr;

const VENDOR_PEN: u32 = 9;
const TYPE_RECORD_TEMPLATE: u16 = 400;

/// Options Template for Information Element type records (RFC 5610 Section
/// 3.9): privateEnterpriseNumber and informationElementId as Scope Fields
const TYPE_RECORD_SPECS: &[Spec] = &[
    (346, 4, None),        // privateEnterpriseNumber [scope]
    (303, 2, None),        // informationElementId [scope]
    (339, 1, None),        // informationElementDataType
    (344, 1, None),        // informationElementSemantics
    (345, 2, None),        // informationElementUnits
    (341, VARIABLE, None), // informationElementName
    (340, VARIABLE, None), // informationElementDescription
];

/// Encode one type record for TYPE_RECORD_SPECS
fn type_record(pen: u32, id: u16, data_type: u8, semantics: u8, name: &str) -> Vec<u8> {
    let mut out = pen.to_be_bytes().to_vec();
    out.extend_from_slice(&id.to_be_bytes());
    out.push(data_type);
    out.push(semantics);
    out.extend_from_slice(&1u16.to_be_bytes()); // units: octets
    out.extend_from_slice(&varlen(name.as_bytes()));
    out.extend_from_slice(&varlen(b"a vendor element"));
    out
}

/// Message defining the type record Options Template and sending records
fn type_records(records: &[Vec<u8>]) -> MessageBuilder {
    MessageBuilder::new()
        .options_template(TYPE_RECORD_TEMPLATE, 2, TYPE_RECORD_SPECS)
        .data(TYPE_RECORD_TEMPLATE, &records.concat())
}

/// Decode `encoded` as the single field of a Data Record with Template 256
fn decode_field(decoder: &mut Decoder, spec: Spec, encoded: &[u8]) -> FieldValue {
    let message = decoder
        .decode(
            &MessageBuilder::new()
                .template(256, &[spec])
                .data(256, encoded)
                .build(),
        )
        .unwrap();
    let value = message.data_records().next().unwrap().fields[0]
        .value
        .clone();
    value
}

#[test]
fn test_rfc5610_information_elements() {
    // The IANA elements used by type records (RFC 5610 Table 4)
    for (id, name) in [
        (303, "informationElementId"),
        (339, "informationElementDataType"),
        (340, "informationElementDescription"),
        (341, "informationElementName"),
        (342, "informationElementRangeBegin"),
        (343, "informationElementRangeEnd"),
        (344, "informationElementSemantics"),
        (345, "informationElementUnits"),
        (346, "privateEnterpriseNumber"),
    ] {
        assert_eq!(lookup(id).unwrap().name, name);
    }
}

#[test]
fn test_unknown_enterprise_element_is_raw() {
    let mut decoder = Decoder::new();
    assert_eq!(
        decode_field(&mut decoder, (100, 2, Some(VENDOR_PEN)), &[0, 42]),
        FieldValue::Raw(vec![0, 42])
    );
}

#[test]
fn test_registered_element() {
    let mut decoder = Decoder::new();
    decoder
        .register_enterprise_element(
            EnterpriseElement::new(VENDOR_PEN, 100, "vendorOctets", DataType::Unsigned64)
                .with_semantics(DataTypeSemantics::DeltaCounter),
        )
        .unwrap();

    // Reduced-size encoding applies as for IANA elements
    assert_eq!(
        decode_field(&mut decoder, (100, 2, Some(VENDOR_PEN)), &[0x01, 0x00]),
        FieldValue::Unsigned(256)
    );
    let spec = ipfix_parser::FieldSpecifier {
        information_element_identifier: 100,
        field_length: 2,
        enterprise_number: Some(VENDOR_PEN),
    };
    assert_eq!(decoder.field_name(1, &spec), Some("vendorOctets"));
    let element = decoder.enterprise_element(7, VENDOR_PEN, 100).unwrap();
    assert_eq!(element.source, ElementSource::Registered);
    // Same element ID under another PEN is a different element
    assert_eq!(
        decode_field(&mut decoder, (100, 2, Some(10)), &[0x01, 0x00]),
        FieldValue::Raw(vec![0x01, 0x00])
    );
}

#[test]
fn test_registered_element_in_basic_list() {
    let mut decoder = Decoder::new();
    decoder
        .register_enterprise_element(EnterpriseElement::new(
            VENDOR_PEN,
            100,
            "vendorAddress",
            DataType::Ipv4Address,
        ))
        .unwrap();
    // basicList (291) of the enterprise element
    let mut list = vec![0x03];
    list.extend_from_slice(&(100u16 | 0x8000).to_be_bytes());
    list.extend_from_slice(&4u16.to_be_bytes());
    list.extend_from_slice(&VENDOR_PEN.to_be_bytes());
    list.extend_from_slice(&[192, 0, 2, 1]);
    let FieldValue::BasicList(list) =
        decode_field(&mut decoder, (291, VARIABLE, None), &varlen(&list))
    else {
        panic!("Expected a basicList");
    };
    assert_eq!(
        list.basic_list_content,
        vec![FieldValue::Ipv4Address(Ipv4Addr::new(192, 0, 2, 1))]
    );
}

#[test]
fn test_register_rejects_reverse_and_iana_elements() {
    let mut decoder = Decoder::new();
    // Reverse PEN (RFC 5103)
    assert!(decoder
        .register_enterprise_element(EnterpriseElement::new(29305, 1, "x", DataType::String))
        .is_err());
    // sourceIPv4Address is defined by IANA
    assert!(decoder
        .register_enterprise_element(EnterpriseElement::new(0, 8, "x", DataType::String))
        .is_err());
    // 15-bit identifiers only
    assert!(decoder
        .register_enterprise_element(EnterpriseElement::new(
            VENDOR_PEN,
            0x8000,
            "x",
            DataType::String
        ))
        .is_err());
}

#[test]
fn test_register_iana_element_newer_than_registry() {
    // An IANA element assigned after this crate's registry snapshot
    let mut decoder = Decoder::new();
    decoder
        .register_enterprise_element(EnterpriseElement::new(
            0,
            30000,
            "futureElement",
            DataType::Unsigned32,
        ))
        .unwrap();
    assert_eq!(
        decode_field(&mut decoder, (30000, 4, None), &[0, 0, 0, 7]),
        FieldValue::Unsigned(7)
    );
}

#[test]
fn test_type_record_is_learned() {
    let mut decoder = Decoder::new();
    let message = decoder
        .decode(
            &type_records(&[type_record(VENDOR_PEN, 100, 2, 3, "vendorPackets")])
                .template(256, &[(100, 2, Some(VENDOR_PEN))])
                .data(256, &[0x00, 0x2A])
                .build(),
        )
        .unwrap();

    // The type record is still returned as a regular Options Data Record
    let records: Vec<_> = message.data_records().collect();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].scope_field_count, 2);
    assert_eq!(records[1].fields[0].value, FieldValue::Unsigned(42));

    assert_eq!(decoder.learned_element_count(), 1);
    let element = decoder.enterprise_element(1, VENDOR_PEN, 100).unwrap();
    assert_eq!(
        element,
        &EnterpriseElement {
            enterprise_number: VENDOR_PEN,
            id: 100,
            name: Some("vendorPackets".to_string()),
            data_type: DataType::Unsigned16,
            semantics: Some(DataTypeSemantics::DeltaCounter),
            units: Some(1),
            range_begin: None,
            range_end: None,
            description: Some("a vendor element".to_string()),
            source: ElementSource::TypeRecord,
        }
    );
}

#[test]
fn test_type_record_applies_to_following_data_sets() {
    let mut decoder = Decoder::new();
    let message = decoder
        .decode(
            &MessageBuilder::new()
                .template(256, &[(100, 2, Some(VENDOR_PEN))])
                .data(256, &[0x00, 0x01])
                .options_template(TYPE_RECORD_TEMPLATE, 2, TYPE_RECORD_SPECS)
                .data(
                    TYPE_RECORD_TEMPLATE,
                    &type_record(VENDOR_PEN, 100, 2, 0, "vendorPort"),
                )
                .data(256, &[0x00, 0x02])
                .build(),
        )
        .unwrap();
    let values: Vec<_> = message
        .data_records()
        .filter(|r| r.template_id == 256)
        .map(|r| r.fields[0].value.clone())
        .collect();
    assert_eq!(
        values,
        vec![FieldValue::Raw(vec![0x00, 0x01]), FieldValue::Unsigned(2)]
    );
}

#[test]
fn test_type_record_does_not_replace_registered_definition() {
    // RFC 5610 Section 3.9: a type record MUST NOT replace the Collecting
    // Process's own definition
    let mut decoder = Decoder::new();
    decoder
        .register_enterprise_element(EnterpriseElement::new(
            VENDOR_PEN,
            100,
            "registered",
            DataType::Unsigned16,
        ))
        .unwrap();
    decoder
        .decode(&type_records(&[type_record(VENDOR_PEN, 100, 13, 0, "learned")]).build())
        .unwrap();
    assert_eq!(decoder.learned_element_count(), 0);
    assert_eq!(
        decode_field(&mut decoder, (100, 2, Some(VENDOR_PEN)), &[0x00, 0x05]),
        FieldValue::Unsigned(5)
    );
}

#[test]
fn test_type_record_does_not_replace_iana_element() {
    // sourceIPv4Address (8) described as a string
    let mut decoder = Decoder::new();
    decoder
        .decode(&type_records(&[type_record(0, 8, 13, 0, "notAnAddress")]).build())
        .unwrap();
    assert_eq!(decoder.learned_element_count(), 0);
    assert_eq!(
        decode_field(&mut decoder, (8, 4, None), &[192, 0, 2, 1]),
        FieldValue::Ipv4Address(Ipv4Addr::new(192, 0, 2, 1))
    );
}

#[test]
fn test_type_record_for_reverse_pen_is_ignored() {
    let mut decoder = Decoder::new();
    decoder
        .decode(&type_records(&[type_record(29305, 100, 2, 0, "reverse")]).build())
        .unwrap();
    assert_eq!(decoder.learned_element_count(), 0);
}

#[test]
fn test_identical_type_records_are_accepted() {
    let record = type_record(VENDOR_PEN, 100, 2, 0, "vendorPort");
    let mut decoder = Decoder::new();
    decoder
        .decode(&type_records(&[record.clone(), record.clone()]).build())
        .unwrap();
    decoder.decode(&type_records(&[record]).build()).unwrap();
    assert_eq!(decoder.learned_element_count(), 1);
}

#[test]
fn test_conflicting_type_records_are_ignored() {
    // RFC 5610 Section 3.9: Information Elements with conflicting type
    // information MUST be ignored
    let mut decoder = Decoder::new();
    decoder
        .decode(
            &type_records(&[
                type_record(VENDOR_PEN, 100, 2, 0, "vendorPort"),
                type_record(VENDOR_PEN, 100, 13, 0, "vendorPort"),
            ])
            .build(),
        )
        .unwrap();
    assert_eq!(decoder.learned_element_count(), 0);
    assert!(decoder.enterprise_element(1, VENDOR_PEN, 100).is_none());
    assert_eq!(
        decode_field(&mut decoder, (100, 2, Some(VENDOR_PEN)), &[0x00, 0x05]),
        FieldValue::Raw(vec![0x00, 0x05])
    );

    // The element stays ignored, even if the first definition is sent again
    decoder
        .decode(&type_records(&[type_record(VENDOR_PEN, 100, 2, 0, "vendorPort")]).build())
        .unwrap();
    assert_eq!(decoder.learned_element_count(), 0);
}

#[test]
fn test_invalid_semantics_are_ignored() {
    // RFC 5610 Section 3.10: an ipv4Address (18) cannot be a deltaCounter (3)
    let mut decoder = Decoder::new();
    decoder
        .decode(&type_records(&[type_record(VENDOR_PEN, 100, 18, 3, "bad")]).build())
        .unwrap();
    assert_eq!(decoder.learned_element_count(), 0);
}

#[test]
fn test_unknown_data_type_or_semantics_are_ignored() {
    let mut decoder = Decoder::new();
    decoder
        .decode(
            &type_records(&[
                type_record(VENDOR_PEN, 100, 200, 0, "unknownType"),
                type_record(VENDOR_PEN, 101, 2, 200, "unknownSemantics"),
            ])
            .build(),
        )
        .unwrap();
    assert_eq!(decoder.learned_element_count(), 0);
}

#[test]
fn test_name_with_nul_character_is_ignored() {
    // RFC 5610 Section 4: names with NUL characters MUST be ignored; the type
    // information is still used
    let mut decoder = Decoder::new();
    decoder
        .decode(&type_records(&[type_record(VENDOR_PEN, 100, 2, 0, "bad\0name")]).build())
        .unwrap();
    let element = decoder.enterprise_element(1, VENDOR_PEN, 100).unwrap();
    assert_eq!(element.name, None);
    assert_eq!(element.data_type, DataType::Unsigned16);
}

#[test]
fn test_type_record_requires_scope_fields() {
    // informationElementId and privateEnterpriseNumber MUST be Scope Fields:
    // here only the PEN is
    let mut decoder = Decoder::new();
    decoder
        .decode(
            &MessageBuilder::new()
                .options_template(TYPE_RECORD_TEMPLATE, 1, TYPE_RECORD_SPECS)
                .data(
                    TYPE_RECORD_TEMPLATE,
                    &type_record(VENDOR_PEN, 100, 2, 0, "vendorPort"),
                )
                .build(),
        )
        .unwrap();
    assert_eq!(decoder.learned_element_count(), 0);
}

#[test]
fn test_type_records_are_scoped_to_observation_domain() {
    let mut decoder = Decoder::new();
    decoder
        .decode(
            &type_records(&[type_record(VENDOR_PEN, 100, 2, 0, "vendorPort")])
                .domain(1)
                .build(),
        )
        .unwrap();
    assert!(decoder.enterprise_element(1, VENDOR_PEN, 100).is_some());
    assert!(decoder.enterprise_element(2, VENDOR_PEN, 100).is_none());
    let message = decoder
        .decode(
            &MessageBuilder::new()
                .domain(2)
                .template(256, &[(100, 2, Some(VENDOR_PEN))])
                .data(256, &[0x00, 0x05])
                .build(),
        )
        .unwrap();
    assert_eq!(
        message.data_records().next().unwrap().fields[0].value,
        FieldValue::Raw(vec![0x00, 0x05])
    );
}

#[test]
fn test_clear_keeps_registered_definitions() {
    let mut decoder = Decoder::new();
    decoder
        .register_enterprise_element(EnterpriseElement::new(
            VENDOR_PEN,
            1,
            "registered",
            DataType::Unsigned8,
        ))
        .unwrap();
    decoder
        .decode(&type_records(&[type_record(VENDOR_PEN, 2, 2, 0, "learned")]).build())
        .unwrap();
    assert_eq!(decoder.learned_element_count(), 1);

    decoder.remove_observation_domain(1);
    assert_eq!(decoder.learned_element_count(), 0);
    decoder
        .decode(&type_records(&[type_record(VENDOR_PEN, 2, 2, 0, "learned")]).build())
        .unwrap();
    decoder.clear();
    assert_eq!(decoder.learned_element_count(), 0);
    assert!(decoder.enterprise_element(1, VENDOR_PEN, 1).is_some());
}

#[test]
fn test_learned_elements_are_bounded() {
    let mut decoder = Decoder::with_config(DecoderConfig {
        max_enterprise_elements: 2,
        ..DecoderConfig::default()
    });
    let records: Vec<_> = (100..110)
        .map(|id| type_record(VENDOR_PEN, id, 2, 0, "vendorElement"))
        .collect();
    let message = decoder.decode(&type_records(&records).build()).unwrap();
    // Extra type records are ignored, not an error
    assert!(matches!(message.sets[1], Set::Data { .. }));
    assert_eq!(decoder.learned_element_count(), 2);
}

#[test]
fn test_semantics_restrictions() {
    // RFC 5610 Section 3.10
    use DataTypeSemantics as S;
    let valid = |data_type, semantics| {
        EnterpriseElement::new(VENDOR_PEN, 1, "x", data_type)
            .with_semantics(semantics)
            .has_valid_semantics()
    };
    // Any value is valid for unsigned types
    for s in DataTypeSemantics::ALL {
        assert!(valid(DataType::Unsigned32, s));
    }
    // Any value except flags for signed types
    assert!(valid(DataType::Signed32, S::DeltaCounter));
    assert!(!valid(DataType::Signed32, S::Flags));
    // Any value except identifier or flags for floating-point types
    assert!(valid(DataType::Float64, S::Quantity));
    assert!(!valid(DataType::Float64, S::Identifier));
    assert!(!valid(DataType::Float64, S::Flags));
    // Only default for other types
    assert!(valid(DataType::String, S::Default));
    assert!(!valid(DataType::Ipv4Address, S::Identifier));
    // Lists (RFC 6313) accept the list semantics
    assert!(valid(DataType::BasicList, S::List));
    // No semantics is always valid
    assert!(EnterpriseElement::new(VENDOR_PEN, 1, "x", DataType::MacAddress).has_valid_semantics());
}

#[test]
fn test_data_type_and_semantics_from_value() {
    assert_eq!(DataType::from_value(18), Some(DataType::Ipv4Address));
    assert_eq!(DataType::from_value(23), Some(DataType::Unsigned256));
    assert_eq!(DataType::from_value(24), None);
    assert_eq!(
        DataTypeSemantics::from_value(3),
        Some(DataTypeSemantics::DeltaCounter)
    );
    assert_eq!(DataTypeSemantics::from_value(9), None);
}

#[test]
fn test_enterprise_bit_with_pen_zero_is_not_iana() {
    // PEN 0 is reserved: a field with the Enterprise bit set and PEN 0 is
    // neither an IANA element nor a match for PEN 0 definitions (which
    // describe IANA elements newer than the registry, sent without the
    // Enterprise bit)
    let mut decoder = Decoder::new();
    decoder
        .register_enterprise_element(EnterpriseElement::new(
            0,
            30000,
            "futureElement",
            DataType::Unsigned32,
        ))
        .unwrap();
    assert_eq!(
        decode_field(&mut decoder, (30000, 4, Some(0)), &[0, 0, 0, 7]),
        FieldValue::Raw(vec![0, 0, 0, 7])
    );
    // sourceIPv4Address with the Enterprise bit and PEN 0
    assert_eq!(
        decode_field(&mut decoder, (8, 4, Some(0)), &[192, 0, 2, 1]),
        FieldValue::Raw(vec![192, 0, 2, 1])
    );
    let spec = ipfix_parser::FieldSpecifier {
        information_element_identifier: 30000,
        field_length: 4,
        enterprise_number: Some(0),
    };
    assert_eq!(decoder.field_name(1, &spec), None);
}

#[test]
fn test_semantics_restrictions_exhaustive() {
    // RFC 5610 Section 3.10, for every data type it covers and every semantics
    use DataType::*;
    use DataTypeSemantics as S;
    for data_type in DataType::ALL {
        for semantics in DataTypeSemantics::ALL {
            let expected = match data_type {
                // "Any value is valid for unsigned"
                Unsigned8 | Unsigned16 | Unsigned32 | Unsigned64 => true,
                // "Any value except flags is valid for signed"
                Signed8 | Signed16 | Signed32 | Signed64 => semantics != S::Flags,
                // "Any value except identifier or flags is valid for floating-point"
                Float32 | Float64 => !matches!(semantics, S::Identifier | S::Flags),
                // "Only default is valid for all other" RFC 5610 data types
                OctetArray | Boolean | MacAddress | String | DateTimeSeconds
                | DateTimeMilliseconds | DateTimeMicroseconds | DateTimeNanoseconds
                | Ipv4Address | Ipv6Address => semantics == S::Default,
                // Data types defined after RFC 5610 (documented deviation)
                Unsigned256 => true,
                BasicList | SubTemplateList | SubTemplateMultiList => {
                    matches!(semantics, S::Default | S::List)
                }
            };
            let element =
                EnterpriseElement::new(VENDOR_PEN, 1, "x", data_type).with_semantics(semantics);
            assert_eq!(
                element.has_valid_semantics(),
                expected,
                "{:?} with {:?}",
                data_type,
                semantics
            );
        }
    }
}

/// Encode a Set
fn set(set_id: u16, content: &[u8]) -> Vec<u8> {
    let mut out = set_id.to_be_bytes().to_vec();
    out.extend_from_slice(&((content.len() + 4) as u16).to_be_bytes());
    out.extend_from_slice(content);
    out
}

#[test]
fn test_rfc5610_appendix_a_example() {
    // The example of RFC 5610 Appendix A: initialTCPFlags (14) and
    // unionTCPFlags (15) are enterprise-specific flags. The example leaves the
    // Private Enterprise Number unspecified.
    const PEN: u32 = 12345;
    let mut message = MessageBuilder::new().build();

    // Figure 1: Template with enterprise-specific IEs (Length = 52)
    let mut template = vec![0x01, 0x00, 0x00, 0x09]; // Template ID 256, Field Count 9
    for (id, length) in [(150u16, 4u16), (8, 4), (12, 4), (7, 2), (11, 2), (85, 4)] {
        template.extend_from_slice(&id.to_be_bytes());
        template.extend_from_slice(&length.to_be_bytes());
    }
    for id in [14u16, 15] {
        template.extend_from_slice(&(id | 0x8000).to_be_bytes());
        template.extend_from_slice(&1u16.to_be_bytes());
        template.extend_from_slice(&PEN.to_be_bytes());
    }
    template.extend_from_slice(&[0x00, 0x04, 0x00, 0x01]); // protocolIdentifier
    let template_set = set(2, &template);
    assert_eq!(template_set.len(), 52);

    // Figure 2: Information Element Type Options Template, with Errata 4731
    // (Length = 30, Field Count = 5) and a variable-length name (65535, the
    // figure says 65536)
    let mut options = vec![0x01, 0x01, 0x00, 0x05, 0x00, 0x02]; // ID 257, 5 fields, 2 scope
    for (id, length) in [(346u16, 4u16), (303, 2), (339, 1), (344, 1), (341, 65535)] {
        options.extend_from_slice(&id.to_be_bytes());
        options.extend_from_slice(&length.to_be_bytes());
    }
    let options_set = set(3, &options);
    assert_eq!(options_set.len(), 30);

    // The two type records (Length = 50)
    let mut records = Vec::new();
    for (id, name) in [(14u16, "initialTCPFlags"), (15, "unionTCPFlags")] {
        records.extend_from_slice(&PEN.to_be_bytes());
        records.extend_from_slice(&id.to_be_bytes());
        records.extend_from_slice(&[0x01, 0x05]); // unsigned8, flags
        records.extend_from_slice(&varlen(name.as_bytes()));
    }
    let type_record_set = set(257, &records);
    assert_eq!(type_record_set.len(), 50);

    // A flow described by Template 256: SYN first, then SYN|ACK|FIN union
    let mut flow = Vec::new();
    flow.extend_from_slice(&1_700_000_000u32.to_be_bytes());
    flow.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
    flow.extend_from_slice(&[0xC0, 0x00, 0x00, 0x50]);
    flow.extend_from_slice(&1500u32.to_be_bytes());
    flow.extend_from_slice(&[0x02, 0x13, 0x06]);

    for s in [template_set, options_set, type_record_set, set(256, &flow)] {
        message.extend(s);
    }
    let length = message.len() as u16;
    message[2..4].copy_from_slice(&length.to_be_bytes());

    let mut decoder = Decoder::new();
    let decoded = decoder.decode(&message).unwrap();
    assert_eq!(decoder.learned_element_count(), 2);

    let element = decoder.enterprise_element(1, PEN, 14).unwrap();
    assert_eq!(element.name.as_deref(), Some("initialTCPFlags"));
    assert_eq!(element.data_type, DataType::Unsigned8);
    assert_eq!(element.semantics, Some(DataTypeSemantics::Flags));

    let flow = decoded
        .data_records()
        .find(|r| r.template_id == 256)
        .unwrap();
    assert_eq!(
        flow.get_by_id(14, Some(PEN)),
        Some(&FieldValue::Unsigned(0x02))
    );
    assert_eq!(
        flow.get_by_id(15, Some(PEN)),
        Some(&FieldValue::Unsigned(0x13))
    );
    assert_eq!(
        decoder.field_name(1, &flow.fields[7].specifier),
        Some("unionTCPFlags")
    );
}
