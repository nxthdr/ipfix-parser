//! Specification validation tests
//!
//! This module validates the IPFIX parser implementation against the IANA
//! IPFIX registries and the RFC documents. It downloads the registries and
//! RFCs and compares them with the Rust implementation.
//!
//! Run with: `cargo test --test specs_test -- --ignored --nocapture`
//! Or use: `make specs-validate`

mod specs;
