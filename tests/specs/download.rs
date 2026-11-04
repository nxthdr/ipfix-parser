//! Download and cache of the specification documents

use std::fs;
use std::path::{Path, PathBuf};

/// A specification document to download and validate against
#[derive(Debug, Clone)]
pub struct SpecDocument {
    pub name: &'static str,
    pub url: &'static str,
    /// Immutable documents (RFCs) are read from the cache when present.
    /// Living documents (IANA registries) are always downloaded, so that the
    /// validation detects new or changed registrations.
    pub immutable: bool,
}

/// RFCs validated against the implementation (wire structures and tables)
pub const RFC_SPECS: &[SpecDocument] = &[
    SpecDocument {
        name: "rfc7011",
        url: "https://www.rfc-editor.org/rfc/rfc7011.txt",
        immutable: true,
    },
    SpecDocument {
        name: "rfc6313",
        url: "https://www.rfc-editor.org/rfc/rfc6313.txt",
        immutable: true,
    },
    SpecDocument {
        name: "rfc5610",
        url: "https://www.rfc-editor.org/rfc/rfc5610.txt",
        immutable: true,
    },
];

/// IANA IPFIX Information Elements registry (CSV)
pub const IANA_INFORMATION_ELEMENTS: SpecDocument = SpecDocument {
    name: "ipfix-information-elements.csv",
    url: "https://www.iana.org/assignments/ipfix/ipfix-information-elements.csv",
    immutable: false,
};

/// IANA IPFIX registries (XML), for the data types, semantics, Set IDs and
/// Version Numbers sub-registries
pub const IANA_IPFIX_REGISTRY: SpecDocument = SpecDocument {
    name: "ipfix.xml",
    url: "https://www.iana.org/assignments/ipfix/ipfix.xml",
    immutable: false,
};

pub fn cache_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/specs/cache")
}

/// Fetch a document, using the cache for immutable documents. Every download
/// is written to the cache for inspection.
pub fn fetch(spec: &SpecDocument) -> String {
    let dir = cache_dir();
    let path = dir.join(spec.name);
    if spec.immutable {
        if let Ok(content) = fs::read_to_string(&path) {
            return content;
        }
    }

    println!("Downloading {} from {}", spec.name, spec.url);
    let content = ureq::get(spec.url)
        .call()
        .unwrap_or_else(|e| panic!("Failed to download {}: {}", spec.url, e))
        .body_mut()
        .read_to_string()
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", spec.url, e));

    fs::create_dir_all(&dir).expect("Failed to create cache directory");
    fs::write(&path, &content).expect("Failed to write cache file");
    content
}

/// Fetch an RFC by name (e.g. `rfc7011`)
pub fn fetch_rfc(name: &str) -> String {
    let spec = RFC_SPECS
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("Unknown RFC {}", name));
    fetch(spec)
}
