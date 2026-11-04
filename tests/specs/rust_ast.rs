//! Extract struct metadata from the Rust source files using `syn`

use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Metadata of a Rust struct with named fields
#[derive(Debug, Clone)]
pub struct StructMetadata {
    pub name: String,
    /// Doc comment lines (leading space removed)
    pub doc: Vec<String>,
    /// Field names, in declaration order
    pub fields: Vec<String>,
}

fn doc_lines(attrs: &[syn::Attribute]) -> Vec<String> {
    attrs
        .iter()
        .filter(|a| a.path().is_ident("doc"))
        .filter_map(|a| match &a.meta {
            syn::Meta::NameValue(nv) => match &nv.value {
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(s),
                    ..
                }) => Some(s.value()),
                _ => None,
            },
            _ => None,
        })
        .map(|line| line.strip_prefix(' ').unwrap_or(&line).to_string())
        .collect()
}

/// Parse all `.rs` files of a directory and index their structs by name
pub fn parse_structs(dir: &Path) -> HashMap<String, StructMetadata> {
    let mut structs = HashMap::new();
    let mut paths: Vec<_> = fs::read_dir(dir)
        .expect("Failed to read source directory")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "rs"))
        .collect();
    paths.sort();

    for path in paths {
        let source = fs::read_to_string(&path).expect("Failed to read source file");
        let file = syn::parse_file(&source)
            .unwrap_or_else(|e| panic!("Failed to parse {}: {}", path.display(), e));
        for item in file.items {
            if let syn::Item::Struct(s) = item {
                let fields = match &s.fields {
                    syn::Fields::Named(named) => named
                        .named
                        .iter()
                        .map(|f| f.ident.as_ref().unwrap().to_string())
                        .collect(),
                    _ => Vec::new(),
                };
                let name = s.ident.to_string();
                structs.insert(
                    name.clone(),
                    StructMetadata {
                        name,
                        doc: doc_lines(&s.attrs),
                        fields,
                    },
                );
            }
        }
    }
    structs
}

/// Convert an RFC field name to a Rust field name:
/// `Observation Domain ID` -> `observation_domain_id`,
/// `basicList Content` -> `basic_list_content`
pub fn to_snake_case(name: &str) -> String {
    name.split_whitespace()
        .map(|word| {
            if word.chars().all(|c| !c.is_lowercase()) {
                // Acronyms (ID, E)
                return word.to_lowercase();
            }
            let mut out = String::new();
            for (i, c) in word.chars().enumerate() {
                if c.is_uppercase() && i > 0 {
                    out.push('_');
                }
                out.extend(c.to_lowercase());
            }
            out
        })
        .collect::<Vec<_>>()
        .join("_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_snake_case() {
        assert_eq!(to_snake_case("Export Time"), "export_time");
        assert_eq!(
            to_snake_case("Observation Domain ID"),
            "observation_domain_id"
        );
        assert_eq!(to_snake_case("basicList Content"), "basic_list_content");
        assert_eq!(
            to_snake_case("subTemplateList Content"),
            "sub_template_list_content"
        );
        assert_eq!(
            to_snake_case("Information Element identifier"),
            "information_element_identifier"
        );
    }

    #[test]
    fn test_parse_models() {
        let structs = parse_structs(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src/models"));
        let header = structs
            .get("MessageHeader")
            .expect("MessageHeader not found");
        assert_eq!(header.fields[0], "version");
        assert!(header.doc.iter().any(|l| l.contains("Export Time")));
    }
}
