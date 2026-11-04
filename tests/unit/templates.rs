//! Templates, Options Templates and Template management - RFC 7011 Sections 3.4 and 8

use super::helpers::{MessageBuilder, VARIABLE};
use ipfix_parser::models::{OptionsTemplateRecord, TemplateRecord};
use ipfix_parser::{
    parse_message, Decoder, DecoderConfig, FieldSpecifier, ParseError, Set, Transport,
};

/// Decoder for a TCP Transport Session, where Template Withdrawals apply
fn tcp_decoder() -> Decoder {
    Decoder::with_config(DecoderConfig {
        transport: Transport::Tcp,
        ..DecoderConfig::default()
    })
}

/// Decoder for a UDP Transport Session with a Template lifetime
fn udp_decoder_with_lifetime(lifetime: u32) -> Decoder {
    Decoder::with_config(DecoderConfig {
        transport: Transport::Udp,
        template_lifetime: Some(lifetime),
        ..DecoderConfig::default()
    })
}

#[test]
fn test_template_record() {
    let data = MessageBuilder::new()
        .template(
            256,
            &[(8, 4, None), (82, VARIABLE, None), (1, 4, Some(29305))],
        )
        .build();
    let message = parse_message(&data).unwrap();
    let Set::Template { header, records } = &message.sets[0] else {
        panic!("Expected a Template Set");
    };
    assert_eq!(header.set_id, 2);
    assert_eq!(header.length, 4 + 4 + 4 + 4 + 8);
    assert_eq!(
        records,
        &vec![TemplateRecord {
            template_id: 256,
            field_count: 3,
            field_specifiers: vec![
                FieldSpecifier {
                    information_element_identifier: 8,
                    field_length: 4,
                    enterprise_number: None,
                },
                FieldSpecifier {
                    information_element_identifier: 82,
                    field_length: VARIABLE,
                    enterprise_number: None,
                },
                FieldSpecifier {
                    information_element_identifier: 1,
                    field_length: 4,
                    enterprise_number: Some(29305),
                },
            ],
        }]
    );
    let specs = &records[0].field_specifiers;
    assert!(specs[1].is_variable_length());
    assert!(specs[2].is_reverse());
    assert_eq!(
        specs[2].information_element().unwrap().name,
        "octetDeltaCount"
    );
}

#[test]
fn test_template_set_with_several_records_and_padding() {
    let mut content = Vec::new();
    for id in [256u16, 257] {
        content.extend_from_slice(&id.to_be_bytes());
        content.extend_from_slice(&1u16.to_be_bytes());
        content.extend_from_slice(&[0x00, 0x04, 0x00, 0x01]); // protocolIdentifier, 1
    }
    content.extend_from_slice(&[0, 0]); // padding
    let data = MessageBuilder::new().set(2, &content).build();
    let mut decoder = Decoder::new();
    let message = decoder.decode(&data).unwrap();
    let Set::Template { records, .. } = &message.sets[0] else {
        panic!("Expected a Template Set");
    };
    assert_eq!(records.len(), 2);
    assert_eq!(decoder.template_count(), 2);
}

#[test]
fn test_template_id_below_256_is_invalid() {
    let data = MessageBuilder::new().template(255, &[(8, 4, None)]).build();
    let err = parse_message(&data).unwrap_err();
    assert!(err.to_string().contains("Invalid Template ID 255"));
}

#[test]
fn test_zero_length_template_is_rejected() {
    // RFC 7011 Errata 7413: a Template describing zero-length records is invalid
    let data = MessageBuilder::new().template(256, &[(8, 0, None)]).build();
    let err = parse_message(&data).unwrap_err();
    assert!(err.to_string().contains("zero-length Data Records"));
}

#[test]
fn test_truncated_field_specifiers() {
    // Field Count says 2, only one Field Specifier present
    let mut content = Vec::new();
    content.extend_from_slice(&256u16.to_be_bytes());
    content.extend_from_slice(&2u16.to_be_bytes());
    content.extend_from_slice(&[0x00, 0x08, 0x00, 0x04]);
    let data = MessageBuilder::new().set(2, &content).build();
    assert!(matches!(
        parse_message(&data),
        Err(ParseError::Truncated { .. })
    ));
}

#[test]
fn test_options_template_record() {
    // Scope: observationDomainId (149); value: exportedMessageTotalCount (41)
    let data = MessageBuilder::new()
        .options_template(300, 1, &[(149, 4, None), (41, 8, None)])
        .data(300, &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7])
        .build();
    let message = parse_message(&data).unwrap();
    let Set::OptionsTemplate { records, .. } = &message.sets[0] else {
        panic!("Expected an Options Template Set");
    };
    assert_eq!(
        records[0],
        OptionsTemplateRecord {
            template_id: 300,
            field_count: 2,
            scope_field_count: 1,
            field_specifiers: vec![
                FieldSpecifier {
                    information_element_identifier: 149,
                    field_length: 4,
                    enterprise_number: None,
                },
                FieldSpecifier {
                    information_element_identifier: 41,
                    field_length: 8,
                    enterprise_number: None,
                },
            ],
        }
    );

    let record = message.data_records().next().unwrap();
    assert_eq!(record.scope_field_count, 1);
    assert_eq!(record.scope_fields().len(), 1);
    assert_eq!(record.scope_fields()[0].name(), Some("observationDomainId"));
    assert_eq!(
        record.non_scope_fields()[0].name(),
        Some("exportedMessageTotalCount")
    );
}

#[test]
fn test_options_template_zero_scope_field_count_is_invalid() {
    let data = MessageBuilder::new()
        .options_template(300, 0, &[(149, 4, None)])
        .build();
    let err = parse_message(&data).unwrap_err();
    assert!(err.to_string().contains("Invalid Scope Field Count 0"));
}

#[test]
fn test_options_template_scope_field_count_above_field_count_is_invalid() {
    let data = MessageBuilder::new()
        .options_template(300, 3, &[(149, 4, None)])
        .build();
    assert!(parse_message(&data).is_err());
}

#[test]
fn test_templates_persist_across_messages() {
    let mut decoder = Decoder::new();
    let templates = MessageBuilder::new().template(256, &[(4, 1, None)]).build();
    let data = MessageBuilder::new().data(256, &[17]).build();

    // Without the Template, the Data Set is kept undecoded
    let message = Decoder::new().decode(&data).unwrap();
    assert!(matches!(
        &message.sets[0],
        Set::UndecodedData { payload, .. } if payload == &vec![17]
    ));

    decoder.decode(&templates).unwrap();
    assert!(decoder.has_template(1, 256));
    let message = decoder.decode(&data).unwrap();
    assert_eq!(message.data_records().count(), 1);
}

#[test]
fn test_templates_are_scoped_to_observation_domain() {
    let mut decoder = Decoder::new();
    decoder
        .decode(
            &MessageBuilder::new()
                .domain(1)
                .template(256, &[(4, 1, None)])
                .build(),
        )
        .unwrap();
    let message = decoder
        .decode(&MessageBuilder::new().domain(2).data(256, &[6]).build())
        .unwrap();
    assert!(matches!(message.sets[0], Set::UndecodedData { .. }));
}

#[test]
fn test_template_redefinition() {
    let mut decoder = Decoder::new();
    decoder
        .decode(&MessageBuilder::new().template(256, &[(4, 1, None)]).build())
        .unwrap();
    decoder
        .decode(&MessageBuilder::new().template(256, &[(7, 2, None)]).build())
        .unwrap();
    let message = decoder
        .decode(&MessageBuilder::new().data(256, &[0x00, 0x50]).build())
        .unwrap();
    let record = message.data_records().next().unwrap();
    assert_eq!(record.fields[0].name(), Some("sourceTransportPort"));
    assert_eq!(decoder.template_count(), 1);
}

#[test]
fn test_template_withdrawal() {
    let mut decoder = tcp_decoder();
    decoder
        .decode(
            &MessageBuilder::new()
                .template(256, &[(4, 1, None)])
                .template(257, &[(4, 1, None)])
                .build(),
        )
        .unwrap();
    let message = decoder
        .decode(&MessageBuilder::new().withdrawal(2, 256).build())
        .unwrap();
    let Set::Template { records, .. } = &message.sets[0] else {
        panic!("Expected a Template Set");
    };
    assert!(records[0].is_withdrawal());
    assert!(!decoder.has_template(1, 256));
    assert!(decoder.has_template(1, 257));
}

#[test]
fn test_all_templates_withdrawal_keeps_options_templates() {
    let mut decoder = tcp_decoder();
    decoder
        .decode(
            &MessageBuilder::new()
                .template(256, &[(4, 1, None)])
                .template(257, &[(4, 1, None)])
                .options_template(300, 1, &[(149, 4, None)])
                .build(),
        )
        .unwrap();
    // Template ID 2 in a Template Set withdraws all Templates (RFC 7011 Figure U)
    decoder
        .decode(&MessageBuilder::new().withdrawal(2, 2).build())
        .unwrap();
    assert_eq!(decoder.template_count(), 1);
    assert!(decoder.has_template(1, 300));

    // Template ID 3 in an Options Template Set withdraws all Options Templates
    let message = decoder
        .decode(&MessageBuilder::new().withdrawal(3, 3).build())
        .unwrap();
    let Set::OptionsTemplate { records, .. } = &message.sets[0] else {
        panic!("Expected an Options Template Set");
    };
    assert!(records[0].is_withdrawal());
    assert_eq!(decoder.template_count(), 0);
}

#[test]
fn test_withdrawal_with_invalid_template_id() {
    let data = MessageBuilder::new().withdrawal(2, 100).build();
    assert!(tcp_decoder().decode(&data).is_err());
}

#[test]
fn test_withdrawal_then_data_in_same_message() {
    // RFC 7011 Section 8.1: Template management takes effect in order
    let data = MessageBuilder::new()
        .template(256, &[(4, 1, None)])
        .data(256, &[6])
        .withdrawal(2, 256)
        .data(256, &[17])
        .build();
    let message = tcp_decoder().decode(&data).unwrap();
    assert!(matches!(message.sets[1], Set::Data { .. }));
    assert!(matches!(message.sets[3], Set::UndecodedData { .. }));
}

#[test]
fn test_default_transport_is_udp() {
    assert_eq!(DecoderConfig::default().transport, Transport::Udp);
    assert_eq!(DecoderConfig::default().template_lifetime, None);
}

#[test]
fn test_withdrawals_are_ignored_over_udp() {
    // RFC 7011 Section 8.4: withdrawals MUST be ignored by Collecting Processes
    // collecting via UDP. They are still returned in the parsed Set.
    let mut decoder = Decoder::new();
    decoder
        .decode(
            &MessageBuilder::new()
                .template(256, &[(4, 1, None)])
                .options_template(300, 1, &[(149, 4, None)])
                .build(),
        )
        .unwrap();
    let message = decoder
        .decode(
            &MessageBuilder::new()
                .withdrawal(2, 256)
                .withdrawal(2, 2)
                .withdrawal(3, 3)
                .data(256, &[6])
                .build(),
        )
        .unwrap();
    let Set::Template { records, .. } = &message.sets[0] else {
        panic!("Expected a Template Set");
    };
    assert!(records[0].is_withdrawal());
    assert!(matches!(message.sets[3], Set::Data { .. }));
    assert_eq!(decoder.template_count(), 2);
}

#[test]
fn test_invalid_withdrawal_is_ignored_over_udp() {
    let data = MessageBuilder::new().withdrawal(2, 100).build();
    assert!(parse_message(&data).is_ok());
}

#[test]
fn test_template_last_received() {
    let mut decoder = Decoder::new();
    decoder
        .decode(
            &MessageBuilder::new()
                .export_time(1000)
                .template(256, &[(4, 1, None)])
                .build(),
        )
        .unwrap();
    assert_eq!(decoder.template_last_received(1, 256), Some(1000));

    // A refresh updates the Last Received time
    decoder
        .decode(
            &MessageBuilder::new()
                .export_time(1060)
                .template(256, &[(4, 1, None)])
                .build(),
        )
        .unwrap();
    assert_eq!(decoder.template_last_received(1, 256), Some(1060));
    assert_eq!(decoder.template_last_received(1, 257), None);
}

#[test]
fn test_template_lifetime_over_udp() {
    // RFC 7011 Section 8.4: Templates not refreshed within the lifetime are
    // discarded
    let mut decoder = udp_decoder_with_lifetime(60);
    decoder
        .decode(
            &MessageBuilder::new()
                .export_time(1000)
                .template(256, &[(4, 1, None)])
                .build(),
        )
        .unwrap();

    // Exactly at the lifetime: still valid
    let message = decoder
        .decode(
            &MessageBuilder::new()
                .export_time(1060)
                .data(256, &[6])
                .build(),
        )
        .unwrap();
    assert!(matches!(message.sets[0], Set::Data { .. }));

    // Past the lifetime: expired, the Data Set is undecoded
    let message = decoder
        .decode(
            &MessageBuilder::new()
                .export_time(1061)
                .data(256, &[6])
                .build(),
        )
        .unwrap();
    assert!(matches!(message.sets[0], Set::UndecodedData { .. }));
    assert!(!decoder.has_template(1, 256));
}

#[test]
fn test_template_refresh_extends_lifetime() {
    let mut decoder = udp_decoder_with_lifetime(60);
    for export_time in [1000, 1050, 1100] {
        decoder
            .decode(
                &MessageBuilder::new()
                    .export_time(export_time)
                    .template(256, &[(4, 1, None)])
                    .build(),
            )
            .unwrap();
    }
    let message = decoder
        .decode(
            &MessageBuilder::new()
                .export_time(1150)
                .data(256, &[6])
                .build(),
        )
        .unwrap();
    assert!(matches!(message.sets[0], Set::Data { .. }));
}

#[test]
fn test_template_refreshed_in_same_message_is_not_expired() {
    // The Template is refreshed before the Data Set in the same late Message
    let mut decoder = udp_decoder_with_lifetime(60);
    decoder
        .decode(
            &MessageBuilder::new()
                .export_time(1000)
                .template(256, &[(4, 1, None)])
                .build(),
        )
        .unwrap();
    let message = decoder
        .decode(
            &MessageBuilder::new()
                .export_time(5000)
                .template(256, &[(4, 1, None)])
                .data(256, &[6])
                .build(),
        )
        .unwrap();
    assert!(matches!(message.sets[1], Set::Data { .. }));
}

#[test]
fn test_export_time_going_backwards_does_not_expire() {
    // An Exporter clock going backwards must not expire Templates
    let mut decoder = udp_decoder_with_lifetime(60);
    decoder
        .decode(
            &MessageBuilder::new()
                .export_time(1000)
                .template(256, &[(4, 1, None)])
                .build(),
        )
        .unwrap();
    let message = decoder
        .decode(
            &MessageBuilder::new()
                .export_time(10)
                .data(256, &[6])
                .build(),
        )
        .unwrap();
    assert!(matches!(message.sets[0], Set::Data { .. }));
}

#[test]
fn test_no_expiry_over_tcp() {
    // Templates only expire over UDP
    let mut decoder = Decoder::with_config(DecoderConfig {
        transport: Transport::Tcp,
        template_lifetime: Some(60),
        ..DecoderConfig::default()
    });
    decoder
        .decode(
            &MessageBuilder::new()
                .export_time(1000)
                .template(256, &[(4, 1, None)])
                .build(),
        )
        .unwrap();
    let message = decoder
        .decode(
            &MessageBuilder::new()
                .export_time(9000)
                .data(256, &[6])
                .build(),
        )
        .unwrap();
    assert!(matches!(message.sets[0], Set::Data { .. }));
}

#[test]
fn test_no_expiry_without_lifetime() {
    let mut decoder = Decoder::new();
    decoder
        .decode(
            &MessageBuilder::new()
                .export_time(0)
                .template(256, &[(4, 1, None)])
                .build(),
        )
        .unwrap();
    let message = decoder
        .decode(
            &MessageBuilder::new()
                .export_time(u32::MAX)
                .data(256, &[6])
                .build(),
        )
        .unwrap();
    assert!(matches!(message.sets[0], Set::Data { .. }));
}

#[test]
fn test_expire_templates_with_caller_clock() {
    let mut decoder = udp_decoder_with_lifetime(60);
    decoder
        .decode(
            &MessageBuilder::new()
                .export_time(1000)
                .template(256, &[(4, 1, None)])
                .build(),
        )
        .unwrap();
    decoder
        .decode(
            &MessageBuilder::new()
                .export_time(1050)
                .template(257, &[(4, 1, None)])
                .build(),
        )
        .unwrap();
    // The Exporter went silent: expire with the caller's own clock
    decoder.expire_templates(1080);
    assert!(!decoder.has_template(1, 256));
    assert!(decoder.has_template(1, 257));
}

#[test]
fn test_expiry_frees_template_limit() {
    // Expired Templates no longer count against max_templates
    let mut decoder = Decoder::with_config(DecoderConfig {
        template_lifetime: Some(60),
        max_templates: 1,
        ..DecoderConfig::default()
    });
    decoder
        .decode(
            &MessageBuilder::new()
                .export_time(1000)
                .template(256, &[(4, 1, None)])
                .build(),
        )
        .unwrap();
    decoder
        .decode(
            &MessageBuilder::new()
                .export_time(2000)
                .template(257, &[(4, 1, None)])
                .build(),
        )
        .unwrap();
    assert!(decoder.has_template(1, 257));
}

#[test]
fn test_template_limit() {
    let mut decoder = Decoder::with_config(DecoderConfig {
        max_templates: 2,
        ..DecoderConfig::default()
    });
    decoder
        .decode(
            &MessageBuilder::new()
                .template(256, &[(4, 1, None)])
                .template(257, &[(4, 1, None)])
                .build(),
        )
        .unwrap();
    // Redefining an existing Template is allowed at the limit
    decoder
        .decode(&MessageBuilder::new().template(257, &[(7, 2, None)]).build())
        .unwrap();
    let err = decoder
        .decode(&MessageBuilder::new().template(258, &[(4, 1, None)]).build())
        .unwrap_err();
    assert_eq!(err, ParseError::TemplateLimitExceeded(2));
}

#[test]
fn test_clear_and_remove_observation_domain() {
    let mut decoder = Decoder::new();
    for domain in [1, 2] {
        decoder
            .decode(
                &MessageBuilder::new()
                    .domain(domain)
                    .template(256, &[(4, 1, None)])
                    .build(),
            )
            .unwrap();
    }
    decoder.remove_observation_domain(1);
    assert!(!decoder.has_template(1, 256));
    assert!(decoder.has_template(2, 256));
    decoder.clear();
    assert_eq!(decoder.template_count(), 0);
}

#[test]
fn test_parse_messages_reads_an_ipfix_file() {
    // RFC 5655 Section 7.1: a File Reader applies Template Withdrawals, and
    // accepts Template redefinitions
    let mut data = MessageBuilder::new()
        .template(256, &[(4, 1, None)])
        .template(257, &[(4, 1, None)])
        .build();
    data.extend(MessageBuilder::new().withdrawal(2, 256).build());
    data.extend(MessageBuilder::new().template(257, &[(7, 2, None)]).build());
    data.extend(
        MessageBuilder::new()
            .data(256, &[6])
            .data(257, &[0x00, 0x35])
            .build(),
    );

    let messages = ipfix_parser::parse_messages(&data).unwrap();
    let last = &messages[3];
    assert!(matches!(last.sets[0], Set::UndecodedData { .. }));
    assert_eq!(
        last.data_records()
            .next()
            .unwrap()
            .get("sourceTransportPort"),
        Some(&ipfix_parser::FieldValue::Unsigned(53))
    );
}

#[test]
fn test_file_transport_never_expires() {
    // RFC 5655: an IPFIX File is read as one Transport Session, possibly long
    // after it was written: Templates never expire
    let mut decoder = Decoder::with_config(DecoderConfig {
        transport: Transport::File,
        template_lifetime: Some(60),
        ..DecoderConfig::default()
    });
    decoder
        .decode(
            &MessageBuilder::new()
                .export_time(1000)
                .template(256, &[(4, 1, None)])
                .build(),
        )
        .unwrap();
    let message = decoder
        .decode(
            &MessageBuilder::new()
                .export_time(1_000_000)
                .data(256, &[6])
                .build(),
        )
        .unwrap();
    assert!(matches!(message.sets[0], Set::Data { .. }));
}

#[test]
fn test_file_transport_applies_withdrawals() {
    let mut decoder = Decoder::with_config(DecoderConfig {
        transport: Transport::File,
        ..DecoderConfig::default()
    });
    decoder
        .decode(&MessageBuilder::new().template(256, &[(4, 1, None)]).build())
        .unwrap();
    decoder
        .decode(&MessageBuilder::new().withdrawal(2, 2).build())
        .unwrap();
    assert_eq!(decoder.template_count(), 0);
}
