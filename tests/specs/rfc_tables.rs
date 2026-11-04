//! Validation of RFC tables against the implementation
//!
//! RFC 5610 defines no packet diagram (a type record is a regular Options
//! Data Record), but two tables the parser depends on:
//!
//! - **Table 1** (IE Data Type Values): the `informationElementDataType`
//!   values, which must map to the same [`DataType`] in the implementation;
//! - **Table 4** (IE Type Options): the Information Elements of a type record
//!   and which of them are Scope Fields, which must match the elements the
//!   parser reads (`registry::type_records`).

use super::download::fetch_rfc;
use super::rfc_structures::clean_rfc;
use ipfix_parser::registry::{lookup, lookup_by_name, type_records, DataType};
use regex::Regex;
use std::collections::BTreeSet;

/// Lines of the table whose caption starts with `caption`, from the line
/// containing `start`
fn table_region<'a>(lines: &'a [String], start: &str, caption: &str) -> &'a [String] {
    let begin = lines
        .iter()
        .position(|l| l.contains(start))
        .unwrap_or_else(|| panic!("'{}' not found", start));
    let end = lines[begin..]
        .iter()
        .position(|l| l.trim_start().starts_with(caption))
        .unwrap_or_else(|| panic!("'{}' not found", caption));
    &lines[begin..begin + end]
}

/// RFC 5610 Table 1: (value, data type name)
pub fn parse_data_type_table(lines: &[String]) -> Vec<(u8, String)> {
    let row = Regex::new(r"^\s*\|\s*(\d+)\s*\|\s*([A-Za-z0-9]+)\s*\|\s*$").unwrap();
    table_region(lines, "Table 1 below", "Table 1:")
        .iter()
        .filter_map(|l| row.captures(l))
        .map(|c| (c[1].parse().unwrap(), c[2].to_string()))
        .collect()
}

/// RFC 5610 Table 4: (Information Element name, is a Scope Field)
pub fn parse_type_options_table(lines: &[String]) -> Vec<(String, bool)> {
    let first_cell = Regex::new(r"^\s*\|\s*([^|]*?)\s*\|").unwrap();
    let name = Regex::new(r"^([a-z][A-Za-z]+)").unwrap();
    let mut elements: Vec<(String, bool)> = Vec::new();
    for line in table_region(lines, "in Table 4", "Table 4:") {
        let Some(cell) = first_cell.captures(line).map(|c| c[1].to_string()) else {
            continue;
        };
        if let Some(n) = name.captures(&cell) {
            elements.push((n[1].to_string(), cell.contains("[scope]")));
        } else if cell == "[scope]" {
            // "[scope]" wrapped onto the next line of the same row
            if let Some(last) = elements.last_mut() {
                last.1 = true;
            }
        }
    }
    elements
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires network access
    fn test_validate_rfc5610_tables() {
        let lines = clean_rfc(&fetch_rfc("rfc5610"));
        let mut issues = Vec::new();
        println!("\n=== RFC 5610 Tables Validation ===\n");

        // Table 1: informationElementDataType values
        let data_types = parse_data_type_table(&lines);
        if data_types.len() != 20 {
            issues.push(format!(
                "Table 1: expected 20 data types, found {}",
                data_types.len()
            ));
        }
        for (value, name) in &data_types {
            match DataType::from_value(*value) {
                Some(t) if t.name() == name => {}
                other => issues.push(format!(
                    "Table 1: value {} is {} in RFC 5610, {:?} in the implementation",
                    value, name, other
                )),
            }
        }
        println!("Table 1: {} data types", data_types.len());

        // Table 4: Information Elements of a type record
        let elements = parse_type_options_table(&lines);
        let mut rfc_ids = BTreeSet::new();
        let mut rfc_scope = BTreeSet::new();
        for (name, scope) in &elements {
            match lookup_by_name(name) {
                Some(ie) => {
                    rfc_ids.insert(ie.id);
                    if *scope {
                        rfc_scope.insert(ie.id);
                    }
                }
                None => issues.push(format!("Table 4: {} is not an IANA element", name)),
            }
        }
        let implemented: BTreeSet<u16> = type_records::ELEMENTS.into_iter().collect();
        let implemented_scope: BTreeSet<u16> = type_records::SCOPE_ELEMENTS.into_iter().collect();
        let names = |ids: &BTreeSet<u16>| -> Vec<&str> {
            ids.iter()
                .map(|id| lookup(*id).map_or("?", |ie| ie.name))
                .collect()
        };
        if rfc_ids != implemented {
            issues.push(format!(
                "Table 4 elements differ:\n     RFC 5610: {:?}\n     implemented: {:?}",
                names(&rfc_ids),
                names(&implemented)
            ));
        }
        if rfc_scope != implemented_scope {
            issues.push(format!(
                "Table 4 Scope Fields differ:\n     RFC 5610: {:?}\n     implemented: {:?}",
                names(&rfc_scope),
                names(&implemented_scope)
            ));
        }
        println!(
            "Table 4: {} elements ({} Scope Fields)",
            elements.len(),
            rfc_scope.len()
        );

        if !issues.is_empty() {
            for issue in &issues {
                println!("⚠️ {}", issue);
            }
            panic!(
                "RFC 5610 tables validation failed: {} issue(s)",
                issues.len()
            );
        }
        println!("\n✅ RFC 5610 tables match the implementation");
    }

    const TABLE_4_SAMPLE: &str =
        "   The template SHOULD contain the Information Elements in Table 4,
   below.

   +-------------------------------+-----------------------------------+
   | IE                            | Description                       |
   +-------------------------------+-----------------------------------+
   | informationElementId [scope]  | The Information Element           |
   |                               | identifier.                       |
   | privateEnterpriseNumber       | The Private Enterprise number of  |
   | [scope]                       | the Information Element.          |
   | informationElementName        | The name of the specified         |
   +-------------------------------+-----------------------------------+
                         Table 4: IE Type Options
";

    #[test]
    fn test_parse_type_options_table() {
        let lines = clean_rfc(TABLE_4_SAMPLE);
        assert_eq!(
            parse_type_options_table(&lines),
            vec![
                ("informationElementId".to_string(), true),
                ("privateEnterpriseNumber".to_string(), true),
                ("informationElementName".to_string(), false),
            ]
        );
    }
}
