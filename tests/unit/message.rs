//! Message and Set framing - RFC 7011 Sections 3.1 and 3.3

use super::helpers::{varlen, MessageBuilder, VARIABLE};
use ipfix_parser::models::SetHeader;
use ipfix_parser::{parse_message, parse_messages, FieldValue, MessageHeader, ParseError, Set};
use std::net::Ipv4Addr;

#[test]
fn test_message_header() {
    let data = MessageBuilder::new().domain(7).build();
    let message = parse_message(&data).unwrap();
    assert_eq!(
        message.header,
        MessageHeader {
            version: 10,
            length: 16,
            export_time: 1_700_000_000,
            sequence_number: 42,
            observation_domain_id: 7,
        }
    );
    assert!(message.sets.is_empty());
}

#[test]
fn test_invalid_version() {
    let mut data = MessageBuilder::new().build();
    data[1] = 9; // NetFlow v9
    assert_eq!(parse_message(&data), Err(ParseError::InvalidVersion(9)));
    assert!(parse_message(&data)
        .unwrap_err()
        .to_string()
        .contains("Invalid version"));
}

#[test]
fn test_truncated_header() {
    let data = MessageBuilder::new().build();
    assert!(matches!(
        parse_message(&data[..10]),
        Err(ParseError::Truncated { .. })
    ));
    assert!(parse_message(&[]).is_err());
}

#[test]
fn test_length_smaller_than_header() {
    let mut data = MessageBuilder::new().build();
    data[3] = 8;
    let err = parse_message(&data).unwrap_err();
    assert!(err.to_string().contains("smaller than the Message Header"));
}

#[test]
fn test_length_larger_than_data() {
    let data = MessageBuilder::new().template(256, &[(4, 1, None)]).build();
    assert!(matches!(
        parse_message(&data[..data.len() - 1]),
        Err(ParseError::Truncated { .. })
    ));
}

#[test]
fn test_trailing_octets_after_message_are_ignored() {
    let mut data = MessageBuilder::new().build();
    data.extend_from_slice(&[0xDE, 0xAD]);
    assert!(parse_message(&data).is_ok());
}

#[test]
fn test_set_length_smaller_than_set_header() {
    let mut data = MessageBuilder::new().set(256, &[]).build();
    data[19] = 2; // Set length = 2
    let err = parse_message(&data).unwrap_err();
    assert!(err.to_string().contains("smaller than the Set Header"));
}

#[test]
fn test_set_length_beyond_message() {
    let mut data = MessageBuilder::new().set(256, &[1, 2, 3, 4]).build();
    data[19] = 100;
    assert!(matches!(
        parse_message(&data),
        Err(ParseError::Truncated { .. })
    ));
}

#[test]
fn test_trailing_octets_inside_message() {
    // 2 octets after the last Set cannot hold a Set Header
    let mut data = MessageBuilder::new().set(256, &[1]).build();
    data.extend_from_slice(&[0, 0]);
    data[3] += 2;
    assert!(parse_message(&data).is_err());
}

#[test]
fn test_reserved_set_id() {
    let data = MessageBuilder::new().set(100, &[1, 2, 3, 4]).build();
    let message = parse_message(&data).unwrap();
    assert_eq!(
        message.sets[0],
        Set::Reserved {
            header: SetHeader {
                set_id: 100,
                length: 8
            },
            payload: vec![1, 2, 3, 4],
        }
    );
    assert_eq!(message.sets[0].header().set_id, 100);
}

#[test]
fn test_data_set_with_several_records_and_padding() {
    // Two 5-octet records (sourceIPv4Address, protocolIdentifier) + 3 octets of
    // padding, shorter than a record (RFC 7011 Section 3.3.1)
    let mut content = vec![10, 0, 0, 1, 6, 10, 0, 0, 2, 17];
    content.extend_from_slice(&[0, 0, 0]);
    let data = MessageBuilder::new()
        .template(256, &[(8, 4, None), (4, 1, None)])
        .data(256, &content)
        .build();
    let message = parse_message(&data).unwrap();
    let records: Vec<_> = message.data_records().collect();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[1].get("sourceIPv4Address"),
        Some(&FieldValue::Ipv4Address(Ipv4Addr::new(10, 0, 0, 2)))
    );
    assert_eq!(records[1].template_id, 256);
}

#[test]
fn test_truncated_variable_length_record() {
    // The variable-length prefix announces more octets than the Set holds
    let data = MessageBuilder::new()
        .template(256, &[(82, VARIABLE, None)])
        .data(256, &[10, b'e', b't'])
        .build();
    assert!(matches!(
        parse_message(&data),
        Err(ParseError::Truncated { .. })
    ));
}

#[test]
fn test_parse_messages() {
    let mut data = MessageBuilder::new()
        .template(256, &[(82, VARIABLE, None)])
        .build();
    data.extend(MessageBuilder::new().data(256, &varlen(b"eth0")).build());
    data.extend(MessageBuilder::new().data(256, &varlen(b"eth1")).build());

    // Templates are shared across the Messages of the buffer
    let messages = parse_messages(&data).unwrap();
    assert_eq!(messages.len(), 3);
    assert_eq!(
        messages[2]
            .data_records()
            .next()
            .unwrap()
            .get("interfaceName"),
        Some(&FieldValue::String("eth1".to_string()))
    );
}

#[test]
fn test_parse_messages_truncated_last_message() {
    let mut data = MessageBuilder::new().build();
    data.extend_from_slice(&MessageBuilder::new().build()[..8]);
    assert!(parse_messages(&data).is_err());
}
