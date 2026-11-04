//! Integration tests on real IPFIX exports
//!
//! - `tests/data/ipfix.bin`: generated with softflowd (see `tests/data/README.md`)
//! - Vendor samples: real exports from many vendors, published by the
//!   logstash-codec-netflow project under the Apache-2.0 license. They are
//!   downloaded at a pinned commit into a git-ignored cache rather than vendored,
//!   to keep this repository MIT-only (`make test-vendors`).

use ipfix_parser::{parse_messages, Decoder, FieldValue, Set};
use std::path::Path;

fn read_capture() -> Vec<u8> {
    std::fs::read("tests/data/ipfix.bin").expect("Failed to read tests/data/ipfix.bin")
}

#[test]
fn test_parse_ipfix_bin() {
    let messages = parse_messages(&read_capture()).expect("Failed to parse IPFIX messages");
    assert_eq!(messages.len(), 2);
    for message in &messages {
        assert_eq!(message.header.version, 10);
        assert!(message
            .sets
            .iter()
            .all(|s| !matches!(s, Set::UndecodedData { .. } | Set::Reserved { .. })));
    }
}

#[test]
fn test_templates() {
    let messages = parse_messages(&read_capture()).unwrap();
    let mut templates = Vec::new();
    let mut options_templates = Vec::new();
    for set in messages.iter().flat_map(|m| &m.sets) {
        match set {
            Set::Template { records, .. } => {
                templates.extend(records.iter().map(|t| t.template_id))
            }
            Set::OptionsTemplate { records, .. } => {
                options_templates.extend(records.iter().map(|t| t.template_id))
            }
            _ => {}
        }
    }
    // softflowd: IPv4/IPv6 flow Templates and a Metering Process Options Template
    assert_eq!(templates, vec![1024, 1025, 2048, 2049]);
    assert_eq!(options_templates, vec![256]);
}

#[test]
fn test_all_fields_are_decoded() {
    // Every field of the capture is an IANA element: none should be raw
    let messages = parse_messages(&read_capture()).unwrap();
    let records: Vec<_> = messages.iter().flat_map(|m| m.data_records()).collect();
    assert!(!records.is_empty());
    for record in &records {
        for field in &record.fields {
            assert!(
                field.name().is_some(),
                "Unknown field {:?}",
                field.specifier
            );
            assert!(
                !matches!(field.value, FieldValue::Raw(_)),
                "Undecoded field {:?}",
                field
            );
        }
    }
}

#[test]
fn test_flow_records() {
    let messages = parse_messages(&read_capture()).unwrap();
    let flows: Vec<_> = messages
        .iter()
        .flat_map(|m| m.data_records())
        .filter(|r| r.scope_field_count == 0)
        .collect();

    let ipv4 = flows
        .iter()
        .filter(|r| r.get("sourceIPv4Address").is_some())
        .count();
    let ipv6 = flows
        .iter()
        .filter(|r| r.get("sourceIPv6Address").is_some())
        .count();
    assert!(ipv4 > 0, "Expected IPv4 flows");
    assert!(ipv6 > 0, "Expected IPv6 flows");

    for flow in &flows {
        assert!(matches!(
            flow.get("octetDeltaCount"),
            Some(FieldValue::Unsigned(n)) if *n > 0
        ));
        assert!(matches!(
            flow.get("protocolIdentifier"),
            Some(FieldValue::Unsigned(1 | 6 | 17 | 58))
        ));
    }
}

#[test]
fn test_options_record() {
    let messages = parse_messages(&read_capture()).unwrap();
    let options: Vec<_> = messages
        .iter()
        .flat_map(|m| m.data_records())
        .filter(|r| r.scope_field_count > 0)
        .collect();
    assert_eq!(options.len(), 1);
    assert_eq!(
        options[0].scope_fields()[0].name(),
        Some("meteringProcessId")
    );
}

#[test]
fn test_decoder_sequence_numbers() {
    let mut decoder = Decoder::new();
    let messages = decoder.decode_all(&read_capture()).unwrap();
    // The Sequence Number counts the Data Records sent before the Message
    // (RFC 7011 Errata 4396)
    let first = &messages[0];
    let records = first.data_records().count() as u32;
    let options = first
        .data_records()
        .filter(|r| r.scope_field_count > 0)
        .count() as u32;
    assert!(messages[1].header.sequence_number >= first.header.sequence_number);
    assert!(
        messages[1].header.sequence_number - first.header.sequence_number <= records,
        "{} records ({} options) between sequence numbers {} and {}",
        records,
        options,
        first.header.sequence_number,
        messages[1].header.sequence_number
    );
}

/// logstash-codec-netflow commit the vendor samples are pinned to
const VENDOR_SAMPLES_COMMIT: &str = "c3834617fc5d5f3332eb28ff776507c8acc53747";

/// Vendor exports, as sequences of files decoded in order by one Decoder
/// (Templates first, then Data Sets)
const VENDOR_SAMPLES: &[(&str, &[&str])] = &[
    ("generic", &["ipfix.dat"]),
    (
        "barracuda",
        &[
            "ipfix_test_barracuda_tpl.dat",
            "ipfix_test_barracuda_data256.dat",
        ],
    ),
    (
        "barracuda extended uniflow",
        &[
            "ipfix_test_barracuda_extended_uniflow_tpl256.dat",
            "ipfix_test_barracuda_extended_uniflow_data256.dat",
        ],
    ),
    (
        "ixia",
        &[
            "ipfix_test_ixia_tpldata256.dat",
            "ipfix_test_ixia_tpldata271.dat",
        ],
    ),
    (
        "juniper mx240",
        &[
            "ipfix_test_juniper_mx240_junos151r6s3_opttpl512.dat",
            "ipfix_test_juniper_mx240_junos151r6s3_data512.dat",
        ],
    ),
    (
        "mikrotik",
        &[
            "ipfix_test_mikrotik_tpl.dat",
            "ipfix_test_mikrotik_data258.dat",
            "ipfix_test_mikrotik_data259.dat",
        ],
    ),
    (
        "netscaler",
        &[
            "ipfix_test_netscaler_tpl.dat",
            "ipfix_test_netscaler_data.dat",
        ],
    ),
    (
        "nokia bras",
        &[
            "ipfix_test_nokia_bras_tpl.dat",
            "ipfix_test_nokia_bras_data256.dat",
        ],
    ),
    (
        "openbsd pflow",
        &[
            "ipfix_test_openbsd_pflow_tpl.dat",
            "ipfix_test_openbsd_pflow_data.dat",
        ],
    ),
    (
        "procera",
        &[
            "ipfix_test_procera_tpl52935.dat",
            "ipfix_test_procera_data52935.dat",
        ],
    ),
    (
        "viptela",
        &[
            "ipfix_test_viptela_tpl257.dat",
            "ipfix_test_viptela_data257.dat",
        ],
    ),
    (
        "vmware vds",
        &[
            "ipfix_test_vmware_vds_tpl.dat",
            "ipfix_test_vmware_vds_data264.dat",
            "ipfix_test_vmware_vds_data266.dat",
            "ipfix_test_vmware_vds_data266_267.dat",
        ],
    ),
    (
        "yaf",
        &[
            "ipfix_test_yaf_tpls_option_tpl.dat",
            "ipfix_test_yaf_tpl45841.dat",
            "ipfix_test_yaf_data45841.dat",
            "ipfix_test_yaf_data45873.dat",
            "ipfix_test_yaf_data53248.dat",
        ],
    ),
];

fn fetch_vendor_sample(name: &str) -> Vec<u8> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/cache");
    let path = dir.join(name);
    if let Ok(data) = std::fs::read(&path) {
        return data;
    }
    let url = format!(
        "https://raw.githubusercontent.com/logstash-plugins/logstash-codec-netflow/{}/spec/codecs/{}",
        VENDOR_SAMPLES_COMMIT, name
    );
    let data = ureq::get(&url)
        .call()
        .unwrap_or_else(|e| panic!("Failed to download {}: {}", url, e))
        .body_mut()
        .read_to_vec()
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", url, e));
    std::fs::create_dir_all(&dir).expect("Failed to create cache directory");
    std::fs::write(&path, &data).expect("Failed to write cache file");
    data
}

#[test]
#[ignore] // Requires network access
fn test_vendor_samples() {
    println!("\n=== Vendor Samples ===\n");
    let mut failures = Vec::new();
    for (vendor, files) in VENDOR_SAMPLES {
        let mut decoder = Decoder::new();
        let (mut decoded, mut undecoded_sets, mut raw_fields) = (0, 0, 0);
        let mut error = None;
        for file in *files {
            match decoder.decode_all(&fetch_vendor_sample(file)) {
                Ok(messages) => {
                    for set in messages.iter().flat_map(|m| &m.sets) {
                        if matches!(set, Set::UndecodedData { .. }) {
                            undecoded_sets += 1;
                        }
                    }
                    for record in messages.iter().flat_map(|m| m.data_records()) {
                        decoded += 1;
                        raw_fields += record
                            .fields
                            .iter()
                            .filter(|f| {
                                f.specifier.information_element().is_some()
                                    && matches!(f.value, FieldValue::Raw(_))
                            })
                            .count();
                    }
                }
                Err(e) => {
                    error = Some(format!("{}: {}", file, e));
                    break;
                }
            }
        }
        let ok = error.is_none() && decoded > 0;
        println!(
            "{} {:<28} {:>4} records, {} undecoded sets, {} raw IANA fields{}",
            if ok { "✅" } else { "❌" },
            vendor,
            decoded,
            undecoded_sets,
            raw_fields,
            error
                .as_ref()
                .map(|e| format!(" ({})", e))
                .unwrap_or_default()
        );
        if !ok {
            failures.push(*vendor);
        }
    }
    assert!(failures.is_empty(), "Vendor samples failed: {:?}", failures);
}
