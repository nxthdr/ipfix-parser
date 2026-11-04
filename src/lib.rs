//! IPFIX Parser Library
//!
//! This library provides parsing functionality for IP Flow Information Export
//! (IPFIX) messages as specified in [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011),
//! with the Information Element registry maintained by
//! [IANA](https://www.iana.org/assignments/ipfix/ipfix.xhtml).
//!
//! IPFIX is a template-based protocol: Data Records can only be decoded with a
//! Template that the Exporter sent earlier. The [`Decoder`] keeps a Template
//! cache and should be kept alive for the whole Transport Session (one
//! `Decoder` per Exporter / TCP connection / UDP source). Template management
//! depends on the transport (UDP by default), see [`DecoderConfig`].
//!
//! # Example
//!
//! ```no_run
//! use ipfix_parser::Decoder;
//!
//! let mut decoder = Decoder::new();
//! let data = std::fs::read("ipfix.bin").unwrap();
//! let message = decoder.decode(&data).unwrap();
//! for record in message.data_records() {
//!     println!("{:?}", record.get("sourceIPv4Address"));
//! }
//! ```
//!
//! For a self-contained buffer (Templates and Data Records in the same
//! buffer), [`parse_message`] and [`parse_messages`] can be used directly.

pub mod models;
pub mod parsers;
pub mod registry;

// Re-export commonly used types
pub use models::{DataRecord, Field, FieldSpecifier, FieldValue, Message, MessageHeader, Set};
pub use parsers::{parse_message, parse_messages, Decoder, DecoderConfig, ParseError, Transport};
