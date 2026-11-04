//! Print the IPFIX Messages of a raw binary file (concatenated UDP payloads)
//!
//! Usage: cargo run --example dump -- tests/data/ipfix.bin

use ipfix_parser::{Decoder, Set};

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/ipfix.bin".to_string());
    let data = std::fs::read(&path).expect("Failed to read input file");

    let mut decoder = Decoder::new();
    for message in decoder.decode_all(&data).expect("Failed to decode") {
        println!(
            "Message: domain={} seq={} export_time={} length={}",
            message.header.observation_domain_id,
            message.header.sequence_number,
            message.header.export_time,
            message.header.length
        );
        for set in &message.sets {
            match set {
                Set::Template { records, .. } => {
                    for t in records {
                        println!("  Template {} ({} fields)", t.template_id, t.field_count);
                    }
                }
                Set::OptionsTemplate { records, .. } => {
                    for t in records {
                        println!(
                            "  Options Template {} ({} fields, {} scope)",
                            t.template_id, t.field_count, t.scope_field_count
                        );
                    }
                }
                Set::Data { records, .. } => {
                    for record in records {
                        let fields: Vec<String> = record
                            .fields
                            .iter()
                            .map(|f| {
                                let name = f.name().unwrap_or("?");
                                let reverse = if f.specifier.is_reverse() {
                                    "reverse:"
                                } else {
                                    ""
                                };
                                format!("{}{}={:?}", reverse, name, f.value)
                            })
                            .collect();
                        println!("  Record {}: {}", record.template_id, fields.join(" "));
                    }
                }
                Set::UndecodedData { header, payload } => {
                    println!(
                        "  Undecoded Data Set {} ({} octets)",
                        header.set_id,
                        payload.len()
                    );
                }
                Set::Reserved { header, .. } => println!("  Reserved Set {}", header.set_id),
            }
        }
    }
}
