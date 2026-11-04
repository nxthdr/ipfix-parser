This crate parses IPFIX ([RFC 7011](https://www.rfc-editor.org/rfc/rfc7011)) only. NetFlow v9 and other flow protocols belong in their own crates, one protocol per repository (like `sflow-parser`).

## Updating the IANA Information Elements

The Information Element table (`src/registry/information_elements.rs`) is generated: never edit it by hand. When `make specs-validate` (or the weekly CI run) reports that the table differs from IANA:

1. Run `make registry-update` to regenerate the table from the IANA registry.
2. Review the diff: new elements, changed data types, newly deprecated elements.
3. If IANA added a new **abstract data type** or **data type semantics**, the generated file will not compile. Add the variant to `DataType` / `DataTypeSemantics` in `src/registry/mod.rs` (keeping the IANA registry order and values), decode it in `src/parsers/value.rs`, add a `FieldValue` variant if needed, and add a test in `tests/unit/data_types.rs`.
4. Update the counts in the `README.md` "Information Elements" section and in `tests/specs/README.md`.

## Enterprise-Specific Information Elements

Enterprise-specific (vendor) element definitions live in the `Decoder` (`src/parsers/elements.rs`), never in the generated IANA table. Keep the RFC 5610 precedence: caller-registered definitions, then IANA, always win over type records sent by the Exporter. Vendor-specific definitions are not shipped in this crate: callers register the ones they need.

## Implementing a New Specification

To implement a new IPFIX specification (RFC), follow these steps:

1. Read the specification document and its [errata](https://www.rfc-editor.org/errata_search.php). Errata with the "Verified" status are authoritative; "Held for Document Update" errata may still clarify ambiguous behaviour.
2. Implement the models in the `src/models` directory. Include a doc comment with the RFC figure **copied verbatim** in a ```` ```text ```` block, and stay as close as possible to the specification: field names (snake_case of the RFC field definitions), types (adapted for Rust), and order.
3. Implement the parser in the `src/parsers` directory. Every read must be bounds-checked through `Cursor`, and allocations must be bounded by the input size. A value that does not match its type is kept as `FieldValue::Raw`; only framing errors fail the Message. Document the errata you implement in the module doc comment ("Known Specification Errata").
4. Add unit tests in the `tests/unit` directory, at minimum one test per new structure or data type, using the `MessageBuilder` helpers.
5. See if the integration tests need to be updated (`tests/integration_test.rs`).
6. Add the structure to `RFC_STRUCTURES` in `tests/specs/rfc_structures.rs` (and the RFC to `RFC_SPECS` in `tests/specs/download.rs`). Declare any deviation from the RFC field list with `aliases` / `ignored_rust_fields` and a note explaining why.
7. If a new structure has a new data type to fuzz, add an Information Element of that type to `INFORMATION_ELEMENTS` in `tests/fuzz/fuzz_targets/fuzz_structured.rs`.
8. Update the documentation in the `README.md` file (Specifications, Message Structures, Abstract Data Types tables) and `tests/specs/README.md`.

If the specification itself is inconsistent, document it in `tests/specs/SPEC_ISSUES.md` after checking it is not already a published erratum.

To check that the implementation is correct, please run:

1. `make test` to validate the unit tests.
2. `make test-integration` to validate the integration tests, and `make test-vendors` for the vendor samples.
3. `make specs-validate` to validate the implementation against the IANA registries and the RFCs. If there is any warning, please check if it is due to the implementation or the validation script. In any case, please fix the issue until there is no warning. Avoid doing exceptions to make the tests pass unless it is really justified and well documented.
4. `make coverage` to validate the coverage of the implementation.
5. `make fuzz-all` when the parser changed, to check that it never panics.

Finally, run `make fmt` and `make clippy` and `make build` to validate the code quality and build the project.

## Releasing

Releases are cut with [`cargo-release`](https://github.com/crate-ci/cargo-release) and published to crates.io as the `ipfix-parser` crate. There is **no CI publish workflow**: publishing happens locally, so you need crates.io credentials (`cargo login` once; the API token is stored in `~/.cargo/credentials.toml`).

`main` is ruleset-protected (PRs required), but the `OrganizationAdmin` role has `bypass: always`, so an org owner's local `cargo release` push to `main` is allowed. That is why release commits land directly on `main` rather than via a PR.

To cut a release X.Y.Z (semver: the library is pre-1.0, so a behavioural/robustness change warrants a minor bump):

1. Make sure `main` is checked out, clean, up to date, and green: `make test && make fmt && make clippy && make build` (CI additionally runs `cargo doc` with `-D warnings`, the specs validation, the vendor samples and a fuzz smoke test).
2. Run the release. One command bumps `Cargo.toml`, commits `chore: Release ipfix-parser version X.Y.Z`, runs `cargo publish`, tags `vX.Y.Z`, and pushes `main` + the tag to `origin`:
   ```bash
   cargo release X.Y.Z --execute
   ```
   Omit `--execute` for a dry run that prints every step without publishing or pushing.
3. Create the GitHub Release. `cargo-release` does **not** do this, but every version should have one:
   ```bash
   gh release create vX.Y.Z --generate-notes --latest --verify-tag
   ```
4. Confirm crates.io shows the new version and the GitHub release/tag exist.

Gotchas:
- crates.io is publish-once: the `Cargo.toml` version must not already be published. `cargo publish` hard-fails on a duplicate, and you can only *yank*, never unpublish.
- `cargo publish` runs **before** the git push, so if the push to `main` is rejected the crate is already live. Re-run only the tag/push steps, do not re-publish.
- The published package excludes `.github/`, `benches/`, and `tests/` (see `exclude` in `Cargo.toml`), so CI, workflow, and test-only changes never affect crate contents.
