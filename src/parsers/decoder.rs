//! Message, Set and Template parsing, and the stateful Template cache
//!
//! # Template management (RFC 7011 Section 8)
//!
//! Templates are scoped to a Transport Session and an Observation Domain. A
//! [`Decoder`] represents one Transport Session: create one per Exporter (TCP
//! connection, SCTP association, or UDP source) and keep it alive while the
//! session lasts. Within a [`Decoder`], Templates are keyed by
//! (Observation Domain ID, Template ID).
//!
//! Templates and Template Withdrawals take effect in the order in which they
//! appear in a Message (RFC 7011 Section 8.1), so a Data Set can be decoded
//! with a Template defined earlier in the same Message.
//!
//! # Transport (RFC 7011 Section 8.4)
//!
//! Template management depends on the transport, set with
//! [`DecoderConfig::transport`] ([`Transport::Udp`] by default):
//!
//! - Over UDP, Template Withdrawals MUST be ignored by the Collecting Process.
//!   They are still returned in the parsed [`Set`], but do not change the
//!   cache. This also prevents a spoofed UDP packet from wiping the cache.
//! - Over UDP, Templates not refreshed within
//!   [`DecoderConfig::template_lifetime`] are discarded. Time is the Export
//!   Time of the Message Headers, so decoding stays deterministic and does not
//!   depend on the system clock: a Template is expired when the Export Time of
//!   the current Message is more than the lifetime after the Export Time of
//!   the Message that last carried it. The RFC suggests a lifetime of at least
//!   3 times the Exporter's Template retransmission interval.
//! - Over TCP and SCTP, Templates live until withdrawn or until the Transport
//!   Session ends ([`Decoder::clear`]).
//! - IPFIX Files (RFC 5655) are a serialized Message stream read as one
//!   Transport Session. A File Reader must support the union of the Template
//!   management features of all transports (RFC 5655 Section 7.1): Templates
//!   can be redefined, Template Withdrawals are applied, and Templates never
//!   expire.
//!
//! # Known Specification Errata
//!
//! - **RFC 7011 Errata 7413 (Section 3.4.1):** a Template whose Data Records
//!   would be zero octets long is rejected. Otherwise every octet of a Data Set
//!   would hold infinitely many zero-length records.

use super::elements::ElementTable;
use super::error::{ParseError, Result};
use super::value::{decode_record, DecodeContext};
use super::Cursor;
use crate::models::*;
use crate::registry::{MIN_DATA_SET_ID, OPTIONS_TEMPLATE_SET_ID, TEMPLATE_SET_ID};
use std::collections::HashMap;

/// Length of the IPFIX Message Header, in octets
const MESSAGE_HEADER_LENGTH: usize = 16;

/// Length of the Set Header, in octets
const SET_HEADER_LENGTH: usize = 4;

/// Transport protocol of the Transport Session (RFC 7011 Section 10)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Transport {
    /// UDP: Template Withdrawals are ignored, and Templates can expire (see
    /// [`DecoderConfig::template_lifetime`])
    #[default]
    Udp,
    /// TCP: Template Withdrawals are applied, Templates never expire
    Tcp,
    /// SCTP: Template Withdrawals are applied, Templates never expire
    Sctp,
    /// IPFIX File (RFC 5655): Template Withdrawals are applied, Templates never
    /// expire. One file is one Transport Session.
    File,
}

/// Decoder configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecoderConfig {
    /// Transport protocol of the Transport Session, which drives Template
    /// management (RFC 7011 Section 8.4). Defaults to UDP, the transport of
    /// most deployments.
    pub transport: Transport,
    /// Template lifetime in seconds, for UDP only (RFC 7011 Section 8.4):
    /// Templates not refreshed for longer than this are discarded. `None`
    /// (the default) keeps Templates until they are redefined.
    pub template_lifetime: Option<u32>,
    /// Maximum number of Templates and Options Templates kept in the cache,
    /// across all Observation Domains. Defining a new Template beyond this
    /// limit returns [`ParseError::TemplateLimitExceeded`]; redefining an
    /// existing Template is always allowed.
    pub max_templates: usize,
    /// Maximum nesting depth of structured data (RFC 6313 lists). Deeper lists
    /// are kept as [`FieldValue::Raw`].
    pub max_list_depth: usize,
    /// Maximum number of enterprise-specific Information Element definitions
    /// learned from type records (RFC 5610), across all Observation Domains.
    /// Further type records are ignored.
    pub max_enterprise_elements: usize,
}

impl Default for DecoderConfig {
    fn default() -> Self {
        Self {
            transport: Transport::Udp,
            template_lifetime: None,
            max_templates: 4096,
            max_list_depth: 8,
            max_enterprise_elements: 4096,
        }
    }
}

/// A Template or Options Template stored in the cache
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Template {
    pub(crate) field_specifiers: Vec<FieldSpecifier>,
    /// 0 for (non-options) Templates
    pub(crate) scope_field_count: u16,
    /// Smallest possible encoded Data Record length (variable-length fields
    /// count as one octet)
    pub(crate) min_record_length: usize,
    /// Export Time of the Message that last carried this Template
    pub(crate) last_received: u32,
}

impl Template {
    fn new(field_specifiers: Vec<FieldSpecifier>, scope_field_count: u16) -> Result<Self> {
        let min_record_length = field_specifiers
            .iter()
            .map(|f| {
                if f.is_variable_length() {
                    1
                } else {
                    f.field_length as usize
                }
            })
            .sum();
        if min_record_length == 0 {
            return Err(ParseError::InvalidData(
                "Template describes zero-length Data Records".to_string(),
            ));
        }
        Ok(Self {
            field_specifiers,
            scope_field_count,
            min_record_length,
            last_received: 0,
        })
    }

    fn is_options(&self) -> bool {
        self.scope_field_count > 0
    }
}

pub(crate) type TemplateCache = HashMap<(u32, u16), Template>;

/// Stateful IPFIX decoder holding the Template cache of one Transport Session
#[derive(Debug, Clone, Default)]
pub struct Decoder {
    config: DecoderConfig,
    templates: TemplateCache,
    /// Enterprise-specific Information Element definitions (RFC 5610)
    elements: ElementTable,
    /// Export Time of the last expiry sweep (sweeps run at most once per
    /// second of Export Time)
    last_sweep: Option<u32>,
}

impl Decoder {
    /// Create a decoder with the default configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a decoder with a custom configuration
    pub fn with_config(config: DecoderConfig) -> Self {
        Self {
            config,
            templates: HashMap::new(),
            elements: ElementTable::default(),
            last_sweep: None,
        }
    }

    /// Number of Templates and Options Templates in the cache
    pub fn template_count(&self) -> usize {
        self.templates.len()
    }

    /// Whether a Template (or Options Template) is known for this Observation
    /// Domain and Template ID
    pub fn has_template(&self, observation_domain_id: u32, template_id: u16) -> bool {
        self.templates
            .contains_key(&(observation_domain_id, template_id))
    }

    /// Export Time of the Message that last carried this Template (or Options
    /// Template), i.e. the "Last Received" of RFC 7011 Section 8.4
    pub fn template_last_received(
        &self,
        observation_domain_id: u32,
        template_id: u16,
    ) -> Option<u32> {
        self.templates
            .get(&(observation_domain_id, template_id))
            .map(|t| t.last_received)
    }

    /// Discard the Templates not refreshed within
    /// [`DecoderConfig::template_lifetime`] at time `now` (in seconds since the
    /// UNIX epoch, like the Export Time). This runs automatically for each
    /// decoded Message over UDP; call it to expire Templates with your own
    /// clock, e.g. when an Exporter stopped sending. Does nothing without a
    /// lifetime.
    pub fn expire_templates(&mut self, now: u32) {
        if let Some(lifetime) = self.config.template_lifetime {
            self.templates
                .retain(|_, t| now.saturating_sub(t.last_received) <= lifetime);
        }
    }

    /// Register the definition of an enterprise-specific Information Element
    /// (e.g. from vendor documentation), so that its fields are decoded with
    /// its data type instead of being kept as [`FieldValue::Raw`].
    ///
    /// Registered definitions apply to all Observation Domains, survive
    /// [`clear`](Self::clear), and always take precedence over type records
    /// sent by the Exporter (RFC 5610 Section 3.9). Registering the same
    /// element again replaces the definition. Fails for reverse elements
    /// (PEN 29305) and for IANA elements already in the registry.
    pub fn register_enterprise_element(&mut self, element: EnterpriseElement) -> Result<()> {
        self.elements.register(element)
    }

    /// The definition of an enterprise-specific Information Element: the
    /// registered one, or else the one learned from type records (RFC 5610)
    /// in this Observation Domain. With `enterprise_number` 0, the definition
    /// of an IANA element newer than the registry.
    pub fn enterprise_element(
        &self,
        observation_domain_id: u32,
        enterprise_number: u32,
        id: u16,
    ) -> Option<&EnterpriseElement> {
        self.elements
            .get(observation_domain_id, enterprise_number, id)
    }

    /// Number of enterprise-specific Information Element definitions learned
    /// from type records (RFC 5610), excluding conflicting ones
    pub fn learned_element_count(&self) -> usize {
        self.elements.learned_count()
    }

    /// The name of a field's Information Element: the IANA name (forward name
    /// for reverse elements), or the name of its enterprise-specific
    /// definition
    pub fn field_name(
        &self,
        observation_domain_id: u32,
        specifier: &FieldSpecifier,
    ) -> Option<&str> {
        if let Some(ie) = specifier.information_element() {
            return Some(ie.name);
        }
        let pen = match specifier.enterprise_number {
            None | Some(crate::registry::REVERSE_INFORMATION_ELEMENT_PEN) => 0,
            // PEN 0 with the Enterprise bit set is not an IANA element
            Some(0) => return None,
            Some(pen) => pen,
        };
        self.elements
            .get(
                observation_domain_id,
                pen,
                specifier.information_element_identifier,
            )
            .and_then(|e| e.name.as_deref())
    }

    /// Remove all Templates and learned type records (e.g. at the end of the
    /// Transport Session). Registered definitions are kept.
    pub fn clear(&mut self) {
        self.templates.clear();
        self.elements.clear_learned();
    }

    /// Remove all Templates and learned type records of an Observation Domain
    pub fn remove_observation_domain(&mut self, observation_domain_id: u32) {
        self.templates
            .retain(|(domain, _), _| *domain != observation_domain_id);
        self.elements.remove_domain(observation_domain_id);
    }

    /// Decode one IPFIX Message, updating the Template cache.
    ///
    /// Octets after the Message Length are ignored; use
    /// [`decode_all`](Self::decode_all) for a buffer holding several Messages.
    pub fn decode(&mut self, data: &[u8]) -> Result<Message> {
        let mut cursor = Cursor::new(data);
        let header = parse_message_header(&mut cursor)?;
        let body = cursor.read_bytes(
            header.length as usize - MESSAGE_HEADER_LENGTH,
            "message body",
        )?;

        let now = header.export_time;
        if self.config.transport == Transport::Udp && self.last_sweep != Some(now) {
            self.expire_templates(now);
            self.last_sweep = Some(now);
        }

        let mut sets = Vec::new();
        let mut cursor = Cursor::new(body);
        while !cursor.is_empty() {
            sets.push(self.parse_set(&mut cursor, header.observation_domain_id, now)?);
        }

        Ok(Message { header, sets })
    }

    /// Decode a buffer of consecutive IPFIX Messages (e.g. a TCP stream or an
    /// IPFIX File), updating the Template cache.
    pub fn decode_all(&mut self, data: &[u8]) -> Result<Vec<Message>> {
        let mut messages = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            let message = self.decode(&data[offset..])?;
            offset += message.header.length as usize;
            messages.push(message);
        }
        Ok(messages)
    }

    fn parse_set(&mut self, cursor: &mut Cursor, domain: u32, now: u32) -> Result<Set> {
        let header = SetHeader {
            set_id: cursor.read_u16("set header")?,
            length: cursor.read_u16("set header")?,
        };
        if (header.length as usize) < SET_HEADER_LENGTH {
            return Err(ParseError::InvalidData(format!(
                "Set length {} is smaller than the Set Header",
                header.length
            )));
        }
        let content = cursor.read_bytes(header.length as usize - SET_HEADER_LENGTH, "set")?;
        let mut content = Cursor::new(content);

        match header.set_id {
            TEMPLATE_SET_ID => Ok(Set::Template {
                header,
                records: self.parse_template_set(&mut content, domain, now)?,
            }),
            OPTIONS_TEMPLATE_SET_ID => Ok(Set::OptionsTemplate {
                header,
                records: self.parse_options_template_set(&mut content, domain, now)?,
            }),
            id if id >= MIN_DATA_SET_ID => match self.templates.get(&(domain, id)) {
                Some(template) => {
                    let ctx = DecodeContext {
                        templates: &self.templates,
                        elements: &self.elements,
                        observation_domain_id: domain,
                        max_depth: self.config.max_list_depth,
                    };
                    let mut records = Vec::new();
                    // Records are read until the remaining octets are fewer than the
                    // smallest possible record: those are padding (RFC 7011 Section 3.3.1)
                    while content.remaining() >= template.min_record_length {
                        records.push(decode_record(&ctx, id, template, &mut content, 0)?);
                    }
                    // Information Element type records (RFC 5610) apply to the
                    // following Data Sets
                    for record in records.iter().filter(|r| r.scope_field_count > 0) {
                        self.elements
                            .learn(domain, record, self.config.max_enterprise_elements);
                    }
                    Ok(Set::Data { header, records })
                }
                None => Ok(Set::UndecodedData {
                    header,
                    payload: content.read_rest().to_vec(),
                }),
            },
            _ => Ok(Set::Reserved {
                header,
                payload: content.read_rest().to_vec(),
            }),
        }
    }

    /// Parse a Template Set (RFC 7011 Section 3.4.1) and apply it to the cache
    fn parse_template_set(
        &mut self,
        cursor: &mut Cursor,
        domain: u32,
        now: u32,
    ) -> Result<Vec<TemplateRecord>> {
        let mut records = Vec::new();
        // A Template Record is at least 4 octets: fewer remaining octets are padding
        while cursor.remaining() >= 4 {
            let template_id = cursor.read_u16("template record header")?;
            let field_count = cursor.read_u16("template record header")?;

            if field_count == 0 {
                self.withdraw(domain, template_id, false)?;
                records.push(TemplateRecord {
                    template_id,
                    field_count,
                    field_specifiers: Vec::new(),
                });
                continue;
            }

            check_template_id(template_id)?;
            let field_specifiers = parse_field_specifiers(cursor, field_count)?;
            self.insert(
                domain,
                template_id,
                Template::new(field_specifiers.clone(), 0)?,
                now,
            )?;
            records.push(TemplateRecord {
                template_id,
                field_count,
                field_specifiers,
            });
        }
        Ok(records)
    }

    /// Parse an Options Template Set (RFC 7011 Section 3.4.2.2) and apply it to
    /// the cache
    fn parse_options_template_set(
        &mut self,
        cursor: &mut Cursor,
        domain: u32,
        now: u32,
    ) -> Result<Vec<OptionsTemplateRecord>> {
        let mut records = Vec::new();
        // An Options Template Withdrawal is 4 octets: fewer remaining octets are padding
        while cursor.remaining() >= 4 {
            let template_id = cursor.read_u16("options template record header")?;
            let field_count = cursor.read_u16("options template record header")?;

            if field_count == 0 {
                self.withdraw(domain, template_id, true)?;
                records.push(OptionsTemplateRecord {
                    template_id,
                    field_count,
                    scope_field_count: 0,
                    field_specifiers: Vec::new(),
                });
                continue;
            }

            check_template_id(template_id)?;
            let scope_field_count = cursor.read_u16("options template record header")?;
            if scope_field_count == 0 || scope_field_count > field_count {
                return Err(ParseError::InvalidData(format!(
                    "Invalid Scope Field Count {} for Field Count {}",
                    scope_field_count, field_count
                )));
            }
            let field_specifiers = parse_field_specifiers(cursor, field_count)?;
            self.insert(
                domain,
                template_id,
                Template::new(field_specifiers.clone(), scope_field_count)?,
                now,
            )?;
            records.push(OptionsTemplateRecord {
                template_id,
                field_count,
                scope_field_count,
                field_specifiers,
            });
        }
        Ok(records)
    }

    fn insert(
        &mut self,
        domain: u32,
        template_id: u16,
        mut template: Template,
        now: u32,
    ) -> Result<()> {
        template.last_received = now;
        let key = (domain, template_id);
        if !self.templates.contains_key(&key) && self.templates.len() >= self.config.max_templates {
            return Err(ParseError::TemplateLimitExceeded(self.config.max_templates));
        }
        self.templates.insert(key, template);
        Ok(())
    }

    /// Apply a Template Withdrawal (RFC 7011 Section 8.1). Over UDP,
    /// withdrawals MUST be ignored (RFC 7011 Section 8.4).
    fn withdraw(&mut self, domain: u32, template_id: u16, options: bool) -> Result<()> {
        if self.config.transport == Transport::Udp {
            return Ok(());
        }
        let withdraw_all_id = if options {
            OPTIONS_TEMPLATE_SET_ID
        } else {
            TEMPLATE_SET_ID
        };
        if template_id == withdraw_all_id {
            // All (Options) Templates Withdrawal
            self.templates
                .retain(|(d, _), t| *d != domain || t.is_options() != options);
            Ok(())
        } else if template_id >= MIN_DATA_SET_ID {
            self.templates.remove(&(domain, template_id));
            Ok(())
        } else {
            Err(ParseError::InvalidData(format!(
                "Invalid Template ID {} in Template Withdrawal",
                template_id
            )))
        }
    }
}

/// Parse an IPFIX Message Header (RFC 7011 Section 3.1)
fn parse_message_header(cursor: &mut Cursor) -> Result<MessageHeader> {
    let available = cursor.remaining();
    let header = MessageHeader {
        version: cursor.read_u16("message header")?,
        length: cursor.read_u16("message header")?,
        export_time: cursor.read_u32("message header")?,
        sequence_number: cursor.read_u32("message header")?,
        observation_domain_id: cursor.read_u32("message header")?,
    };
    if header.version != crate::registry::IPFIX_VERSION {
        return Err(ParseError::InvalidVersion(header.version));
    }
    if (header.length as usize) < MESSAGE_HEADER_LENGTH {
        return Err(ParseError::InvalidData(format!(
            "Message length {} is smaller than the Message Header",
            header.length
        )));
    }
    if header.length as usize > available {
        return Err(ParseError::Truncated {
            context: "message",
            needed: header.length as usize,
            available,
        });
    }
    Ok(header)
}

fn check_template_id(template_id: u16) -> Result<()> {
    if template_id < MIN_DATA_SET_ID {
        return Err(ParseError::InvalidData(format!(
            "Invalid Template ID {} (must be > 255)",
            template_id
        )));
    }
    Ok(())
}

/// Parse `field_count` Field Specifiers (RFC 7011 Section 3.2)
fn parse_field_specifiers(cursor: &mut Cursor, field_count: u16) -> Result<Vec<FieldSpecifier>> {
    // Each Field Specifier is at least 4 octets: bound the allocation by the input
    let mut field_specifiers =
        Vec::with_capacity((field_count as usize).min(cursor.remaining() / 4));
    for _ in 0..field_count {
        let (information_element_identifier, enterprise) =
            cursor.read_field_id("field specifier")?;
        let field_length = cursor.read_u16("field specifier")?;
        let enterprise_number = if enterprise {
            Some(cursor.read_u32("field specifier")?)
        } else {
            None
        };
        field_specifiers.push(FieldSpecifier {
            information_element_identifier,
            field_length,
            enterprise_number,
        });
    }
    Ok(field_specifiers)
}

/// Parse a single self-contained IPFIX Message.
///
/// Only Templates defined in the Message itself are used to decode its Data
/// Sets; Data Sets with unknown Templates are returned as
/// [`Set::UndecodedData`]. Use a [`Decoder`] to keep Templates across Messages.
///
/// This uses the default [`DecoderConfig`] ([`Transport::Udp`], the transport
/// of a single datagram): Template Withdrawals are ignored.
pub fn parse_message(data: &[u8]) -> Result<Message> {
    Decoder::new().decode(data)
}

/// Parse a buffer of consecutive IPFIX Messages, sharing Templates across
/// them (as if they belonged to the same Transport Session).
///
/// A buffer of consecutive Messages is read as an IPFIX File (RFC 5655), with
/// [`Transport::File`] semantics: Template Withdrawals are applied and
/// Templates never expire. Compressed files must be decompressed by the
/// caller.
pub fn parse_messages(data: &[u8]) -> Result<Vec<Message>> {
    Decoder::with_config(DecoderConfig {
        transport: Transport::File,
        ..DecoderConfig::default()
    })
    .decode_all(data)
}
