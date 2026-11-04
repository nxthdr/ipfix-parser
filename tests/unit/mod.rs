//! Unit tests organized by module
//!
//! - message: Message Header and Set framing
//! - templates: Template and Options Template parsing and management
//! - data_types: one test per IANA abstract data type
//! - structured_data: RFC 6313 basicList, subTemplateList, subTemplateMultiList
//! - registry: IANA registry lookups and record accessors

mod data_types;
mod helpers;
mod message;
mod registry;
mod structured_data;
mod templates;
