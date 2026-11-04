//! Helpers to build IPFIX Messages in tests

#![allow(dead_code)]

use ipfix_parser::{parse_message, FieldValue, Message, Set};

/// Field Specifier: (Information Element identifier, Field Length, Enterprise Number)
pub type Spec = (u16, u16, Option<u32>);

pub const VARIABLE: u16 = 65535;

/// Encode Field Specifiers (RFC 7011 Section 3.2)
pub fn encode_specs(specs: &[Spec]) -> Vec<u8> {
    let mut out = Vec::new();
    for (id, length, pen) in specs {
        let raw = if pen.is_some() { id | 0x8000 } else { *id };
        out.extend_from_slice(&raw.to_be_bytes());
        out.extend_from_slice(&length.to_be_bytes());
        if let Some(pen) = pen {
            out.extend_from_slice(&pen.to_be_bytes());
        }
    }
    out
}

/// Encode a variable-length value (RFC 7011 Section 7)
pub fn varlen(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if value.len() < 255 {
        out.push(value.len() as u8);
    } else {
        out.push(255);
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(value);
    out
}

/// Builder for an IPFIX Message
#[derive(Debug, Clone)]
pub struct MessageBuilder {
    export_time: u32,
    sequence_number: u32,
    observation_domain_id: u32,
    sets: Vec<u8>,
}

impl Default for MessageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageBuilder {
    pub fn new() -> Self {
        Self {
            export_time: 1_700_000_000,
            sequence_number: 42,
            observation_domain_id: 1,
            sets: Vec::new(),
        }
    }

    pub fn domain(mut self, observation_domain_id: u32) -> Self {
        self.observation_domain_id = observation_domain_id;
        self
    }

    pub fn export_time(mut self, export_time: u32) -> Self {
        self.export_time = export_time;
        self
    }

    /// Append a Set with a raw content
    pub fn set(mut self, set_id: u16, content: &[u8]) -> Self {
        self.sets.extend_from_slice(&set_id.to_be_bytes());
        self.sets
            .extend_from_slice(&((content.len() + 4) as u16).to_be_bytes());
        self.sets.extend_from_slice(content);
        self
    }

    /// Append a Template Set with one Template Record
    pub fn template(self, template_id: u16, specs: &[Spec]) -> Self {
        let mut content = Vec::new();
        content.extend_from_slice(&template_id.to_be_bytes());
        content.extend_from_slice(&(specs.len() as u16).to_be_bytes());
        content.extend_from_slice(&encode_specs(specs));
        self.set(2, &content)
    }

    /// Append an Options Template Set with one Options Template Record
    pub fn options_template(
        self,
        template_id: u16,
        scope_field_count: u16,
        specs: &[Spec],
    ) -> Self {
        let mut content = Vec::new();
        content.extend_from_slice(&template_id.to_be_bytes());
        content.extend_from_slice(&(specs.len() as u16).to_be_bytes());
        content.extend_from_slice(&scope_field_count.to_be_bytes());
        content.extend_from_slice(&encode_specs(specs));
        self.set(3, &content)
    }

    /// Append a Template Withdrawal (Set ID 2) or Options Template Withdrawal
    /// (Set ID 3)
    pub fn withdrawal(self, set_id: u16, template_id: u16) -> Self {
        let mut content = Vec::new();
        content.extend_from_slice(&template_id.to_be_bytes());
        content.extend_from_slice(&0u16.to_be_bytes());
        self.set(set_id, &content)
    }

    /// Append a Data Set
    pub fn data(self, template_id: u16, content: &[u8]) -> Self {
        self.set(template_id, content)
    }

    pub fn build(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&10u16.to_be_bytes());
        out.extend_from_slice(&((self.sets.len() + 16) as u16).to_be_bytes());
        out.extend_from_slice(&self.export_time.to_be_bytes());
        out.extend_from_slice(&self.sequence_number.to_be_bytes());
        out.extend_from_slice(&self.observation_domain_id.to_be_bytes());
        out.extend_from_slice(&self.sets);
        out
    }
}

/// The decoded Data Sets of a Message
pub fn data_sets(message: &Message) -> Vec<&Set> {
    message
        .sets
        .iter()
        .filter(|s| matches!(s, Set::Data { .. }))
        .collect()
}

/// Decode a single value of one Information Element: build a Template with one
/// field and a Data Set with one record holding `encoded` (already including
/// the variable-length prefix if `length` is [`VARIABLE`])
pub fn decode_one(spec: Spec, encoded: &[u8]) -> FieldValue {
    let data = MessageBuilder::new()
        .template(256, &[spec])
        .data(256, encoded)
        .build();
    let message = parse_message(&data).expect("Failed to parse message");
    let mut records = message.data_records();
    let record = records.next().expect("No data record");
    assert!(records.next().is_none(), "Expected a single data record");
    record.fields[0].value.clone()
}
