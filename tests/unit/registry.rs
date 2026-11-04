//! IANA registry lookups and record accessors

use super::helpers::MessageBuilder;
use ipfix_parser::registry::{
    lookup, lookup_by_name, DataType, DataTypeSemantics, Status, INFORMATION_ELEMENTS,
};
use ipfix_parser::{parse_message, FieldValue};

#[test]
fn test_registry_is_sorted_and_unique() {
    assert!(INFORMATION_ELEMENTS.windows(2).all(|w| w[0].id < w[1].id));
}

#[test]
fn test_lookup() {
    let ie = lookup(8).unwrap();
    assert_eq!(ie.name, "sourceIPv4Address");
    assert_eq!(ie.data_type, DataType::Ipv4Address);
    assert_eq!(ie.semantics, Some(DataTypeSemantics::Default));
    assert_eq!(ie.status, Status::Current);

    let ie = lookup(1).unwrap();
    assert_eq!(ie.units, Some("octets"));
    assert_eq!(ie.semantics, Some(DataTypeSemantics::DeltaCounter));

    assert!(lookup(0).is_none());
    assert!(lookup(32767).is_none());
}

#[test]
fn test_lookup_by_name() {
    assert_eq!(lookup_by_name("destinationTransportPort").unwrap().id, 11);
    assert!(lookup_by_name("doesNotExist").is_none());
}

#[test]
fn test_deprecated_elements() {
    assert!(INFORMATION_ELEMENTS
        .iter()
        .any(|ie| ie.status == Status::Deprecated));
}

#[test]
fn test_data_type_names_and_lengths() {
    assert_eq!(DataType::ALL.len(), 24);
    for (i, t) in DataType::ALL.iter().enumerate() {
        assert_eq!(*t as usize, i);
    }
    assert_eq!(DataType::Unsigned256.name(), "unsigned256");
    assert_eq!(DataType::Ipv6Address.default_length(), Some(16));
    assert_eq!(DataType::String.default_length(), None);
    assert_eq!(DataTypeSemantics::SnmpGauge.name(), "snmpGauge");
}

#[test]
fn test_record_accessors() {
    // sourceTransportPort, enterprise element 7 of PEN 9, reverse sourceTransportPort
    let data = MessageBuilder::new()
        .template(256, &[(7, 2, None), (7, 2, Some(9)), (7, 2, Some(29305))])
        .data(256, &[0x00, 0x50, 0xAA, 0xBB, 0x01, 0xBB])
        .build();
    let message = parse_message(&data).unwrap();
    let record = message.data_records().next().unwrap();

    // `get` only matches IANA (non-enterprise, non-reverse) elements
    assert_eq!(
        record.get("sourceTransportPort"),
        Some(&FieldValue::Unsigned(80))
    );
    assert_eq!(
        record.get_by_id(7, Some(9)),
        Some(&FieldValue::Raw(vec![0xAA, 0xBB]))
    );
    assert_eq!(
        record.get_by_id(7, Some(29305)),
        Some(&FieldValue::Unsigned(443))
    );
    assert!(record.fields[1].name().is_none());
    assert_eq!(record.fields[2].name(), Some("sourceTransportPort"));
    assert!(record.fields[2].specifier.is_reverse());
    assert!(record.scope_fields().is_empty());
    assert_eq!(record.non_scope_fields().len(), 3);
}
