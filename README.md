# IPFIX Parser

[![CI Status](https://img.shields.io/github/actions/workflow/status/nxthdr/ipfix-parser/ci.yml?logo=github&label=build)](https://github.com/nxthdr/ipfix-parser/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/ipfix-parser?color=blue&logo=rust)](https://crates.io/crates/ipfix-parser)
[![Docs](https://img.shields.io/docsrs/ipfix-parser?logo=rust)](https://docs.rs/ipfix-parser)
[![Codecov](https://img.shields.io/codecov/c/github/nxthdr/ipfix-parser?logo=codecov)](https://codecov.io/gh/nxthdr/ipfix-parser)
[![License](https://img.shields.io/crates/l/ipfix-parser)](LICENSE)

A dependency-free Rust library for parsing IP Flow Information Export (IPFIX) messages, as specified in [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011).

## Implementation Status

The IPFIX protocol, the full IANA Information Element registry, and the structured data types are implemented.

Each implemented wire structure is validated against the figures and field definitions of its RFC, and the Information Element table is generated from, and validated against, the [IANA IPFIX registry](https://www.iana.org/assignments/ipfix/ipfix.xhtml).

**Status Legend:**
- ✅ Implemented
- ⬜ Not implemented
- 🪦 Deprecated

### Specifications

| Year | Specification | Description | Status |
|------|--------------|-------------|--------|
| 2008 | [RFC 5103](https://www.rfc-editor.org/rfc/rfc5103) | Bidirectional Flow Export (reverse Information Elements) | ✅ |
| 2009 | [RFC 5610](https://www.rfc-editor.org/rfc/rfc5610) | Exporting Type Information for Enterprise-Specific Information Elements | ✅ |
| 2009 | [RFC 5655](https://www.rfc-editor.org/rfc/rfc5655) | IPFIX File Format (reading) | ✅ |
| 2011 | [RFC 6313](https://www.rfc-editor.org/rfc/rfc6313) | Export of Structured Data (basicList, subTemplateList, subTemplateMultiList) | ✅ |
| 2013 | [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011) | IPFIX Protocol: Messages, Sets, Templates, encodings | ✅ |
| 2013 | [RFC 7012](https://www.rfc-editor.org/rfc/rfc7012) | Information Model: abstract data types and semantics | ✅ |
| 2025 | [RFC 9740](https://www.rfc-editor.org/rfc/rfc9740) | `unsigned256` data type (TCP options and IPv6 extension headers) | ✅ |

**Note:** see [RFC Errata](https://www.rfc-editor.org/errata_search.php?rfc=7011) for corrections to published specifications. The following technical errata are implemented:

| Errata | RFC | Behaviour |
|--------|-----|-----------|
| [3232](https://www.rfc-editor.org/errata/eid3232) | RFC 6313 | A subTemplateMultiList Data Records Length below 4 is invalid |
| [4396](https://www.rfc-editor.org/errata/eid4396) | RFC 7011 | The Sequence Number counts Data Records sent *before* the Message |
| [7413](https://www.rfc-editor.org/errata/eid7413) | RFC 7011 | Templates describing zero-length Data Records are rejected |
| [7875](https://www.rfc-editor.org/errata/eid7875) | RFC 7011 | Reduced-size signed integers are sign-extended |
| [4731](https://www.rfc-editor.org/errata/eid4731) | RFC 5610 | Corrected Appendix A example (used as a unit test) |

### Message Structures

| Structure | Specification | Status |
|-----------|---------------|--------|
| Message Header | [RFC 7011 §3.1](https://www.rfc-editor.org/rfc/rfc7011#section-3.1) | ✅ |
| Field Specifier (IANA, enterprise-specific) | [RFC 7011 §3.2](https://www.rfc-editor.org/rfc/rfc7011#section-3.2) | ✅ |
| Set Header, padding | [RFC 7011 §3.3](https://www.rfc-editor.org/rfc/rfc7011#section-3.3) | ✅ |
| Template Record | [RFC 7011 §3.4.1](https://www.rfc-editor.org/rfc/rfc7011#section-3.4.1) | ✅ |
| Options Template Record | [RFC 7011 §3.4.2](https://www.rfc-editor.org/rfc/rfc7011#section-3.4.2) | ✅ |
| Data Record | [RFC 7011 §3.4.3](https://www.rfc-editor.org/rfc/rfc7011#section-3.4.3) | ✅ |
| Variable-length encoding (1 and 3 octets) | [RFC 7011 §7](https://www.rfc-editor.org/rfc/rfc7011#section-7) | ✅ |
| Template Withdrawal, All (Options) Templates Withdrawal (TCP, SCTP, files) | [RFC 7011 §8.1](https://www.rfc-editor.org/rfc/rfc7011#section-8.1) | ✅ |
| Template Withdrawals ignored over UDP | [RFC 7011 §8.4](https://www.rfc-editor.org/rfc/rfc7011#section-8.4) | ✅ |
| Template lifetime over UDP ("Last Received") | [RFC 7011 §8.4](https://www.rfc-editor.org/rfc/rfc7011#section-8.4) | ✅ |
| IPFIX File Reader (union of all transports' Template management) | [RFC 5655 §7.1](https://www.rfc-editor.org/rfc/rfc5655#section-7.1) | ✅ |
| File compression, CMS signatures | [RFC 5655 §5.3, §9](https://www.rfc-editor.org/rfc/rfc5655#section-9) | ⬜ (out of scope: decompress / verify before parsing) |
| Information Element type records, data type / semantics restrictions | [RFC 5610 §3.9, §3.10](https://www.rfc-editor.org/rfc/rfc5610#section-3.9) | ✅ |
| Reverse Information Elements (PEN 29305) | [RFC 5103 §6.1](https://www.rfc-editor.org/rfc/rfc5103#section-6.1) | ✅ |
| basicList | [RFC 6313 §4.5.1](https://www.rfc-editor.org/rfc/rfc6313#section-4.5.1) | ✅ |
| subTemplateList | [RFC 6313 §4.5.2](https://www.rfc-editor.org/rfc/rfc6313#section-4.5.2) | ✅ |
| subTemplateMultiList | [RFC 6313 §4.5.3](https://www.rfc-editor.org/rfc/rfc6313#section-4.5.3) | ✅ |

### Abstract Data Types

All data types of the [IANA registry](https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-information-element-data-types), with reduced-size encoding ([RFC 7011 §6.2](https://www.rfc-editor.org/rfc/rfc7011#section-6.2)) where allowed.

| Value | Name | Specification | Status |
|-------|------|---------------|--------|
| 0 | octetArray | [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011#section-6.1.6) | ✅ |
| 1-4 | unsigned8, unsigned16, unsigned32, unsigned64 | [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011#section-6.1.1) | ✅ |
| 5-8 | signed8, signed16, signed32, signed64 | [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011#section-6.1.1) | ✅ |
| 9 | float32 | [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011#section-6.1.3) | ✅ |
| 10 | float64 | [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011#section-6.1.4) | ✅ |
| 11 | boolean | [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011#section-6.1.5) | ✅ |
| 12 | macAddress | [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011#section-6.1.2) | ✅ |
| 13 | string | [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011#section-6.1.6) | ✅ |
| 14 | dateTimeSeconds | [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011#section-6.1.7) | ✅ |
| 15 | dateTimeMilliseconds | [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011#section-6.1.8) | ✅ |
| 16 | dateTimeMicroseconds | [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011#section-6.1.9) | ✅ |
| 17 | dateTimeNanoseconds | [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011#section-6.1.10) | ✅ |
| 18 | ipv4Address | [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011#section-6.1.2) | ✅ |
| 19 | ipv6Address | [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011#section-6.1.2) | ✅ |
| 20 | basicList | [RFC 6313](https://www.rfc-editor.org/rfc/rfc6313#section-4.5.1) | ✅ |
| 21 | subTemplateList | [RFC 6313](https://www.rfc-editor.org/rfc/rfc6313#section-4.5.2) | ✅ |
| 22 | subTemplateMultiList | [RFC 6313](https://www.rfc-editor.org/rfc/rfc6313#section-4.5.3) | ✅ |
| 23 | unsigned256 | [RFC 9740](https://www.rfc-editor.org/rfc/rfc9740) | ✅ |

### Information Elements

All 502 Information Elements of the [IANA registry](https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-information-elements) are known (17 of them 🪦 deprecated), with their name, data type, semantics, status and units: see [`src/registry/information_elements.rs`](src/registry/information_elements.rs).

The table is generated from the IANA registry with `make registry-update`. The weekly CI run fails when IANA assigns or changes an element, which is the signal to regenerate it.

Values that cannot be decoded with their Information Element's type are kept as `FieldValue::Raw` instead of failing the whole Message. This covers enterprise-specific elements whose type is unknown (see below), lengths not allowed for the type, invalid UTF-8, and lists referencing an unknown Template.

### Enterprise-Specific Information Elements

Enterprise-specific (vendor) Information Elements are not in the IANA registry, so their fields are kept as `FieldValue::Raw` unless the decoder knows their type. Each `Decoder` keeps a table of definitions, filled from two sources:

1. **Registered by the caller**, e.g. from vendor documentation. They are the Collecting Process's "own internal definition": they apply to all Observation Domains, survive `Decoder::clear`, and always take precedence ([RFC 5610 §3.9](https://www.rfc-editor.org/rfc/rfc5610#section-3.9)).
2. **Learned from [RFC 5610](https://www.rfc-editor.org/rfc/rfc5610) type records** sent by the Exporter: Options Data Records scoped by `privateEnterpriseNumber` and `informationElementId`, which describe an element's data type, semantics, units, range, name and description. They apply to the following Data Sets of the same Transport Session and Observation Domain.

```rust
use ipfix_parser::models::EnterpriseElement;
use ipfix_parser::registry::{DataType, DataTypeSemantics};

// From the vendor's documentation: its IANA Private Enterprise Number, and
// the identifier, name and type of the element
let vendor_pen = 12345;
decoder.register_enterprise_element(
    EnterpriseElement::new(vendor_pen, 1, "vendorRoundTripTime", DataType::Unsigned32)
        .with_semantics(DataTypeSemantics::Quantity),
)?;

// Fields of that element now decode as FieldValue::Unsigned, and
// decoder.field_name(domain, &field.specifier) returns its name
```

The example of [RFC 5610 Appendix A](https://www.rfc-editor.org/rfc/rfc5610#appendix-A) is reproduced as a unit test. Type records follow the RFC's rules: they never replace a registered definition or an IANA element, an element with conflicting type records is ignored, invalid data type / semantics combinations ([§3.10](https://www.rfc-editor.org/rfc/rfc5610#section-3.10)) and names with NUL characters are ignored, and the learned table is bounded (`DecoderConfig::max_enterprise_elements`). Registering an element with PEN 0 also lets you decode IANA elements assigned after this crate's registry snapshot.

Most vendors document their elements out-of-band rather than sending type records (none of the 13 vendor samples in the test suite do), so registration is usually what makes their fields decodable.

## Usage

IPFIX is template-based: Data Records can only be decoded with a Template that the Exporter sent earlier. The `Decoder` keeps the Template cache of one Transport Session, so create one per Exporter (TCP connection, or UDP source address) and keep it alive:

```rust
use ipfix_parser::{Decoder, FieldValue};

let mut decoder = Decoder::new();

// For each UDP datagram / IPFIX Message received from this Exporter
let message = decoder.decode(&data)?;
for record in message.data_records() {
    if let Some(FieldValue::Ipv4Address(src)) = record.get("sourceIPv4Address") {
        println!("{} {:?}", src, record.get("octetDeltaCount"));
    }
}
```

Template management depends on the transport ([RFC 7011 §8.4](https://www.rfc-editor.org/rfc/rfc7011#section-8.4)), so tell the decoder which one the session uses. UDP is the default:

```rust
use ipfix_parser::{Decoder, DecoderConfig, Transport};

// UDP (default): Template Withdrawals are ignored, as the RFC requires (this
// also protects the cache from spoofed withdrawals), and Templates not
// refreshed within the lifetime are discarded
let udp = Decoder::with_config(DecoderConfig {
    template_lifetime: Some(1800), // at least 3x the Exporter's refresh interval
    ..DecoderConfig::default()
});

// TCP, SCTP or IPFIX File: Template Withdrawals apply, Templates never expire
let tcp = Decoder::with_config(DecoderConfig {
    transport: Transport::Tcp,
    ..DecoderConfig::default()
});
```

Time is the Export Time of the Message Headers, not the system clock, so decoding is deterministic. `Decoder::template_last_received` exposes when each Template was last refreshed, and `Decoder::expire_templates` expires Templates with your own clock (e.g. when an Exporter goes silent).

Data Sets whose Template is not known yet are returned as `Set::UndecodedData`, so the caller can buffer or drop them ([RFC 7011 §8](https://www.rfc-editor.org/rfc/rfc7011#section-8)). The Template cache is bounded (`DecoderConfig::max_templates`, 4096 by default), as is the nesting depth of structured data (`DecoderConfig::max_list_depth`).

For self-contained buffers, `parse_message` decodes a single Message (UDP semantics), and `parse_messages` reads a buffer of consecutive Messages as an [IPFIX File](https://www.rfc-editor.org/rfc/rfc5655) (`Transport::File` semantics: withdrawals apply, no expiry). A compressed file must be decompressed first.

## Serialization / Deserialization Support

Enables optional serialization and deserialization support for all IPFIX data structures using [serde](https://serde.rs/). This allows you to easily convert parsed IPFIX data to and from JSON, YAML, or any other format supported by serde.

```toml
[dependencies]
ipfix-parser = { version = "0.1", features = ["serde"] }
serde_json = "1.0"
```

Example usage:
```rust
use ipfix_parser::{parse_message, Message};

let message = parse_message(&data)?;

// Serialize to JSON
let json = serde_json::to_string(&message)?;

// Deserialize from JSON
let message: Message = serde_json::from_str(&json)?;
```

## Testing

### Unit & Integration Tests

Run the comprehensive test suite:
```bash
make test              # Run all tests
make test-unit         # Run unit tests only
make test-integration  # Run integration tests only
make test-vendors      # Run integration tests against vendor samples (network)
```

The integration tests decode a [capture generated with softflowd](tests/data/README.md), and real exports from 13 vendors and exporters (YAF, VMware VDS, Citrix NetScaler, Juniper, MikroTik, Nokia, OpenBSD pflow, ...) published by [logstash-codec-netflow](https://github.com/logstash-plugins/logstash-codec-netflow) under the Apache-2.0 license. To keep this repository MIT-only, these samples are downloaded at a pinned commit rather than vendored.

### Fuzz Tests

The project includes comprehensive fuzz testing using `cargo-fuzz`:

```bash
make fuzz-install     # Install fuzzing tools (requires nightly Rust)
make fuzz-single      # Fuzz single Message parsing (60s)
make fuzz-session     # Fuzz a Transport Session: Templates across Messages (60s)
make fuzz-structured  # Fuzz with valid framing and Templates over every data type (60s)
make fuzz-all         # Run all fuzzers (5 minutes each)
```

### Specifications Validation

The project includes comprehensive [validation](tests/specs/README.md) against the IANA IPFIX registries and the RFC documents, using the `syn` crate to parse Rust source files and extract struct metadata:

```bash
make specs-validate   # Validate against IANA and the RFCs
make registry-update  # Regenerate the Information Element table from IANA
```

This validation allowed us to identify [additional specification issues](tests/specs/SPEC_ISSUES.md) that are not yet part of the official errata.

### Benchmarks

Performance benchmarks using Criterion:

```bash
make bench
```

**Results:** ~7.3µs to decode the [test capture](tests/data/README.md) (2 Messages, 31 Data Records of 14 to 16 fields), i.e. ~235ns per Data Record (~230 MiB/s throughput), on an Apple Silicon laptop. Like `sflow-parser`, the parser is not zero-copy (at least for now) and does not use any unsafe code.

## License

This project is licensed under the [MIT License](LICENSE).
