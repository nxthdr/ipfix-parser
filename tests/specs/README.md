# IPFIX Specification Validation Tests

Automated validation tests that verify our Rust implementation against the [IANA IPFIX registries](https://www.iana.org/assignments/ipfix/ipfix.xhtml) and the IPFIX RFCs.

**Status: ✅ 502/502 Information Elements, 24/24 data types, 8/8 RFC structures, 2/2 RFC tables**

## Components

- **`iana_registry.rs`** - Generates the Information Element table from the IANA registry, and validates the table, data types, semantics, Set IDs and Version Number against IANA
- **`rfc_structures.rs`** - Downloads the RFCs, extracts the packet diagrams and field definitions, and validates them against the implementation
- **`rfc_tables.rs`** - Downloads RFC 5610 and validates its data type and type record tables against the implementation
- **`rust_ast.rs`** - Parses Rust source files using `syn` to extract struct metadata (fields and doc comments)
- **`download.rs`** - Downloads the documents into `cache/` (not committed)

## IANA Registries

The IANA registries are machine-readable, so the Information Element table ([`src/registry/information_elements.rs`](../../src/registry/information_elements.rs)) is **generated** from the registry and **validated** against it. Every field of every element (name, data type, semantics, status, units) must match. The IANA registries are never read from the cache: they change over time, and detecting those changes is the point of the validation. CI runs it weekly.

| Registry | Validated against |
|----------|-------------------|
| [IPFIX Information Elements](https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-information-elements) | `registry::INFORMATION_ELEMENTS` (generated) |
| [IPFIX Information Element Data Types](https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-information-element-data-types) | `registry::DataType` |
| [IPFIX Information Element Semantics](https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-information-element-semantics) | `registry::DataTypeSemantics` |
| [IPFIX Set IDs](https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-set-ids) | `registry::TEMPLATE_SET_ID`, `OPTIONS_TEMPLATE_SET_ID`, `MIN_DATA_SET_ID` |
| [IPFIX Version Numbers](https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-version-numbers) | `registry::IPFIX_VERSION` |

The Information Elements of RFC 5610 type records (`informationElementId`, `privateEnterpriseNumber`, `informationElementDataType`, ...) are IANA elements, so they are covered by this validation.

Registry rows that are not decodable Information Elements are skipped: ID ranges and "Reserved" / "Unassigned" / "Assigned for NetFlow v9 compatibility" placeholders, and ElementIDs 416 and 419. Those two were deprecated as duplicates of 352 and 353 and have no name or data type in the registry.

When the validation fails because IANA changed, run:

```bash
make registry-update
```

## RFC Structures

For each wire structure, the validation checks that:

1. The RFC figure (packet diagram) is quoted **verbatim** in the doc comment of the Rust struct.
2. The field definitions following the figure match the Rust struct fields **in order** (e.g. `Observation Domain ID` -> `observation_domain_id`).

| RFC | Figure | Rust structure | Status |
|-----|--------|----------------|--------|
| RFC 7011 | Figure F: IPFIX Message Header Format | `MessageHeader` | ✅ |
| RFC 7011 | Figure G: Field Specifier Format | `FieldSpecifier` | ✅ |
| RFC 7011 | Figure I: Set Header Format | `SetHeader` | ✅ |
| RFC 7011 | Figure K: Template Record Header Format | `TemplateRecord` | ✅ |
| RFC 7011 | Figure N: Options Template Record Header Format | `OptionsTemplateRecord` | ✅ |
| RFC 6313 | Figure 1: basicList Encoding | `BasicList` | ✅ |
| RFC 6313 | Figure 5: subTemplateList Encoding | `SubTemplateList` | ✅ |
| RFC 6313 | Figure 8: subTemplateMultiList Encoding | `SubTemplateMultiList` + `SubTemplateMultiListEntry` | ✅ |

## RFC Tables

RFC 5610 defines no packet diagram of its own (a type record is a regular Options Data Record), but two tables the parser depends on are validated:

| RFC | Table | Validated against | Status |
|-----|-------|-------------------|--------|
| RFC 5610 | Table 1: IE Data Type Values | `registry::DataType` | ✅ |
| RFC 5610 | Table 4: IE Type Options (elements and Scope Fields) | `registry::type_records::{ELEMENTS, SCOPE_ELEMENTS}` | ✅ |

Intentional deviations (for example, the Enterprise bit being represented by `enterprise_number.is_some()`) are declared per structure in `RFC_STRUCTURES`, each with a note explaining why.

## Running Tests

```bash
make specs-validate
```

## Specification Errata

See the [RFC errata](https://www.rfc-editor.org/errata_search.php?rfc=7011) for documented corrections to published specifications. The technical errata implemented by the parser are listed in the [README](../../README.md#specifications).

We've also identified [additional specification issues](SPEC_ISSUES.md) that are not yet part of the official errata.

## References

- [RFC 7011 - IPFIX Protocol Specification](https://www.rfc-editor.org/rfc/rfc7011)
- [RFC 7012 - Information Model for IPFIX](https://www.rfc-editor.org/rfc/rfc7012)
- [RFC 6313 - Export of Structured Data in IPFIX](https://www.rfc-editor.org/rfc/rfc6313)
- [RFC 5103 - Bidirectional Flow Export Using IPFIX](https://www.rfc-editor.org/rfc/rfc5103)
- [IANA IPFIX Entities](https://www.iana.org/assignments/ipfix/ipfix.xhtml)
