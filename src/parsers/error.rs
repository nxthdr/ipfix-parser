//! Parser error types

use std::fmt;

/// Parser error type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The input ended before a structure could be fully read
    Truncated {
        /// Structure being read
        context: &'static str,
        /// Octets needed
        needed: usize,
        /// Octets available
        available: usize,
    },
    /// Version Number is not 10 (IPFIX)
    InvalidVersion(u16),
    /// Invalid data format
    InvalidData(String),
    /// The decoder Template cache is full (see
    /// [`DecoderConfig::max_templates`](crate::DecoderConfig::max_templates))
    TemplateLimitExceeded(usize),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Truncated {
                context,
                needed,
                available,
            } => write!(
                f,
                "Truncated {}: needed {} octets, {} available",
                context, needed, available
            ),
            ParseError::InvalidVersion(v) => {
                write!(f, "Invalid version: {} (expected 10)", v)
            }
            ParseError::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
            ParseError::TemplateLimitExceeded(limit) => {
                write!(f, "Template limit exceeded: {} templates", limit)
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// Result type for parser operations
pub type Result<T> = std::result::Result<T, ParseError>;
