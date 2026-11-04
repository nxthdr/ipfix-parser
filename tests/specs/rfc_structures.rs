//! Validation of the wire structures against the RFC documents
//!
//! For each structure implemented in `src/models`, the RFC is downloaded and:
//!
//! 1. The figure (ASCII packet diagram) is extracted and must appear verbatim
//!    in the doc comment of the Rust struct, so the docs quote the RFC
//!    faithfully.
//! 2. The field definitions following the figure (e.g. `Export Time`) are
//!    converted to snake_case and must match the Rust struct fields, in order.
//!
//! # Special Cases
//!
//! Deviations from the RFC field list are declared per structure in
//! [`RFC_STRUCTURES`] (`aliases` and `ignored_rust_fields`), each with a reason.

use super::download::fetch_rfc;
use super::rust_ast::{parse_structs, to_snake_case, StructMetadata};
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;

/// A wire structure defined by an RFC figure
pub struct RfcStructure {
    /// RFC name (see `download::RFC_SPECS`)
    pub rfc: &'static str,
    /// Figure label, e.g. `Figure F`
    pub figure: &'static str,
    /// Rust structs whose fields, concatenated, implement the figure. The
    /// figure must be quoted in the doc comment of the first one.
    pub rust_structs: &'static [&'static str],
    /// RFC field name -> Rust field name (`None` if not stored as a field)
    pub aliases: &'static [(&'static str, Option<&'static str>)],
    /// Rust fields that are not RFC field definitions
    pub ignored_rust_fields: &'static [&'static str],
    /// Why the special cases above exist
    pub notes: &'static str,
}

pub const RFC_STRUCTURES: &[RfcStructure] = &[
    RfcStructure {
        rfc: "rfc7011",
        figure: "Figure F",
        rust_structs: &["MessageHeader"],
        aliases: &[],
        ignored_rust_fields: &[],
        notes: "",
    },
    RfcStructure {
        rfc: "rfc7011",
        figure: "Figure G",
        rust_structs: &["FieldSpecifier"],
        aliases: &[("E", None)],
        ignored_rust_fields: &[],
        notes: "The Enterprise bit is represented by `enterprise_number.is_some()`.",
    },
    RfcStructure {
        rfc: "rfc7011",
        figure: "Figure I",
        rust_structs: &["SetHeader"],
        aliases: &[],
        ignored_rust_fields: &[],
        notes: "",
    },
    RfcStructure {
        rfc: "rfc7011",
        figure: "Figure K",
        rust_structs: &["TemplateRecord"],
        aliases: &[],
        ignored_rust_fields: &["field_specifiers"],
        notes: "Figure K is the Template Record Header; the Field Specifiers follow it (Figure J).",
    },
    RfcStructure {
        rfc: "rfc7011",
        figure: "Figure N",
        rust_structs: &["OptionsTemplateRecord"],
        aliases: &[],
        ignored_rust_fields: &["field_specifiers"],
        notes: "Figure N is the Options Template Record Header; the Field Specifiers follow it (Figure M).",
    },
    RfcStructure {
        rfc: "rfc6313",
        figure: "Figure 1",
        rust_structs: &["BasicList"],
        aliases: &[],
        ignored_rust_fields: &["enterprise_number"],
        notes: "The Enterprise Number is only present with the Enterprise bit set (Figure 2).",
    },
    RfcStructure {
        rfc: "rfc6313",
        figure: "Figure 5",
        rust_structs: &["SubTemplateList"],
        aliases: &[],
        ignored_rust_fields: &[],
        notes: "",
    },
    RfcStructure {
        rfc: "rfc6313",
        figure: "Figure 8",
        rust_structs: &["SubTemplateMultiList", "SubTemplateMultiListEntry"],
        aliases: &[("Data Record X.M", Some("data_records"))],
        ignored_rust_fields: &["entries"],
        notes: "Each Template ID / Data Records Length block is a SubTemplateMultiListEntry.",
    },
];

/// RFC text without page breaks, page headers and page footers
pub fn clean_rfc(text: &str) -> Vec<String> {
    let page_line = Regex::new(r"^(\S.*\[Page \d+\]|RFC \d{4} {2,}.*\S)$").unwrap();
    text.replace('\u{c}', "")
        .lines()
        .filter(|l| !page_line.is_match(l))
        .map(|l| l.trim_end().to_string())
        .collect()
}

/// Index of the caption line of a figure (skipping the table of contents)
fn find_caption(lines: &[String], figure: &str) -> Option<usize> {
    let caption = Regex::new(&format!(r"^\s*{}:\s", regex::escape(figure))).unwrap();
    lines
        .iter()
        .position(|l| caption.is_match(l) && !l.contains("...."))
}

/// The packet diagram above a figure caption (trimmed, non-empty lines)
pub fn extract_figure(lines: &[String], figure: &str) -> Vec<String> {
    let caption = find_caption(lines, figure).unwrap_or_else(|| panic!("{} not found", figure));
    let is_diagram = |l: &str| {
        let t = l.trim_start();
        t.is_empty() || t.starts_with('+') || t.starts_with('|') || t.starts_with('0')
    };
    let mut start = caption;
    while start > 0 && is_diagram(&lines[start - 1]) {
        start -= 1;
    }
    lines[start..caption]
        .iter()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// The field definitions following a figure: short lines indented by 3 spaces
/// whose next non-empty line is indented by 6 spaces, up to the next section
/// or figure.
pub fn extract_definitions(lines: &[String], figure: &str) -> Vec<String> {
    let caption = find_caption(lines, figure).unwrap_or_else(|| panic!("{} not found", figure));
    let section = Regex::new(r"^\d+(\.\d+)*\.\s").unwrap();
    let next_figure = Regex::new(r"^\s*Figure [A-Z0-9]+:\s").unwrap();
    let definition = Regex::new(r"^ {3}([A-Za-z].{0,40})$").unwrap();

    let mut definitions = Vec::new();
    for i in caption + 1..lines.len() {
        let line = &lines[i];
        if section.is_match(line) || next_figure.is_match(line) {
            break;
        }
        let Some(name) = definition.captures(line).map(|c| c[1].to_string()) else {
            continue;
        };
        if name.ends_with('.') || name.ends_with(':') {
            continue;
        }
        let next = lines[i + 1..].iter().find(|l| !l.trim().is_empty());
        if next.is_some_and(|l| l.starts_with("      ")) {
            definitions.push(name);
        }
    }
    definitions
}

/// Validate one structure, returning the list of issues
pub fn validate_structure(
    spec: &RfcStructure,
    rfc_lines: &[String],
    structs: &HashMap<String, StructMetadata>,
) -> Vec<String> {
    let mut issues = Vec::new();
    let rust: Vec<&StructMetadata> = spec
        .rust_structs
        .iter()
        .filter_map(|name| {
            let s = structs.get(*name);
            if s.is_none() {
                issues.push(format!("Rust struct {} not found", name));
            }
            s
        })
        .collect();
    if !issues.is_empty() {
        return issues;
    }

    // 1. The figure is quoted verbatim in the doc comment
    let figure = extract_figure(rfc_lines, spec.figure);
    let doc: Vec<String> = rust[0].doc.iter().map(|l| l.trim().to_string()).collect();
    if figure.is_empty() {
        issues.push(format!("{} diagram not found in {}", spec.figure, spec.rfc));
    } else if !doc.windows(figure.len()).any(|w| w == figure.as_slice()) {
        issues.push(format!(
            "Doc comment of {} does not quote {} of {} verbatim",
            rust[0].name, spec.figure, spec.rfc
        ));
    }

    // 2. The field definitions match the Rust fields, in order
    let expected: Vec<String> = extract_definitions(rfc_lines, spec.figure)
        .iter()
        .filter_map(
            |name| match spec.aliases.iter().find(|(rfc_name, _)| rfc_name == name) {
                Some((_, rust_name)) => rust_name.map(str::to_string),
                None => Some(to_snake_case(name)),
            },
        )
        .collect();
    let actual: Vec<String> = rust
        .iter()
        .flat_map(|s| s.fields.iter())
        .filter(|f| !spec.ignored_rust_fields.contains(&f.as_str()))
        .cloned()
        .collect();
    if expected.is_empty() {
        issues.push(format!(
            "No field definitions found after {} in {}",
            spec.figure, spec.rfc
        ));
    } else if expected != actual {
        issues.push(format!(
            "Fields differ:\n     {} {}: {:?}\n     Rust {}: {:?}",
            spec.rfc,
            spec.figure,
            expected,
            spec.rust_structs.join(" + "),
            actual
        ));
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires network access
    fn test_validate_against_rfcs() {
        let structs = parse_structs(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src/models"));
        let mut rfcs: HashMap<&str, Vec<String>> = HashMap::new();

        println!("\n=== RFC Structures Validation ===\n");
        let mut total_issues = 0;
        for spec in RFC_STRUCTURES {
            let lines = rfcs
                .entry(spec.rfc)
                .or_insert_with(|| clean_rfc(&fetch_rfc(spec.rfc)));
            let issues = validate_structure(spec, lines, &structs);
            let emoji = if issues.is_empty() { "✅" } else { "⚠️" };
            println!(
                "{} {} {} -> {}",
                emoji,
                spec.rfc,
                spec.figure,
                spec.rust_structs.join(" + ")
            );
            if !spec.notes.is_empty() {
                println!("     note: {}", spec.notes);
            }
            for issue in &issues {
                println!("     {}", issue);
            }
            total_issues += issues.len();
        }

        if total_issues > 0 {
            panic!(
                "RFC structures validation failed: {} issue(s). All implemented \
                 structures must quote their RFC figure and match its field definitions.",
                total_issues
            );
        }
        println!(
            "\n✅ All {} RFC structures validated successfully!",
            RFC_STRUCTURES.len()
        );
    }

    const RFC_SAMPLE: &str = "3.3.2.  Set Header Format

   Every Set contains a common header.

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |          Set ID               |          Length               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                        Figure I: Set Header Format

   Each Set Header field is exported in network format.  The fields are
   defined as follows:

   Set ID

      Identifies the Set.

Claise, et al.               Standards Track                   [Page 19]
\u{c}
RFC 7011              IPFIX Protocol Specification        September 2013


   Length

      Total length of the Set.

3.4.  Record Format
";

    #[test]
    fn test_extract_figure_and_definitions() {
        let lines = clean_rfc(RFC_SAMPLE);
        let figure = extract_figure(&lines, "Figure I");
        assert_eq!(figure.len(), 5);
        assert_eq!(
            figure[3],
            "|          Set ID               |          Length               |"
        );
        assert_eq!(
            extract_definitions(&lines, "Figure I"),
            vec!["Set ID", "Length"]
        );
    }
}
