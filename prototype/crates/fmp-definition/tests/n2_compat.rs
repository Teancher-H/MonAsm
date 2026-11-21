//! The one narrowing from a checked bundle to the H1 entry (`ADR-0128` §10).
//!
//! The negative half of this row is a compile-time fact: `compat.rs` carries a
//! `compile_fail` doctest for the absent `definition()` accessor, and this crate
//! has no public constructor that turns a `Definition` into a `CheckedBundle`.
//! What a runtime test can add is the positive guarantee and the dependency edge.

mod support;

use std::path::Path;

use fmp_model::canonical::canonical_bytes;
use fmp_model::definition;
use support::*;

/// `the_compat_bridge_cannot_widen_back` — the executed value is the digested
/// value, the consumer crates do not depend on this builder, and reading the
/// embedded definition directly is legal but is not bundle evidence.
#[test]
fn the_compat_bridge_cannot_widen_back() {
    let tree = TempTree::new("compat-bridge");
    let fixture = ManifestFixture::default();
    write_release_package(&tree, &fixture);
    let spec = SpecFixture::for_packages(vec![SpecEntryFixture::of(&tree, &fixture)]);
    let bundle = checked(&tree, &spec);

    // Positive: the adapter returns the very definition the merge produced.
    let narrowed = fmp_definition::compat::as_legacy_definition(&bundle);
    assert_eq!(narrowed.digest(), bundle.definition_digest());

    // The validator and materializer are consumers of a definition, not of the
    // builder; if either depended on `fmp-definition`, a package contract change
    // could reach the runtime by Cargo graph rather than by a merged bundle.
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate lives under prototype/crates");
    for consumer in ["fmp-validate", "fmp-materialize"] {
        let manifest = crates.join(consumer).join("Cargo.toml");
        let text = std::fs::read_to_string(&manifest)
            .unwrap_or_else(|error| panic!("read {}: {error}", manifest.display()));
        assert!(
            !text.contains("fmp-definition"),
            "{consumer} must not depend on the builder"
        );
    }

    // Bypass: `bundle_json()` plus `definition::read` compiles and yields the
    // same execution rules, but the resulting `Definition` carries no bundle
    // identity, ownership map or closure fact, so no report may cite it as one.
    let sealed = bundle.bundle_json();
    let embedded = sealed
        .get("definition")
        .expect("the sealed bundle carries the merged definition")
        .clone();
    let bypass = definition::read(&canonical_bytes(&embedded))
        .expect("the embedded definition is a legal document");
    assert_eq!(bypass.digest(), bundle.definition_digest());
}
