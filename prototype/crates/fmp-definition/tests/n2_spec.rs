//! The spec, lock and sealed negative rows of `ADR-0128` §8 and §8.2.
//!
//! These are the rows that can be decided from a document plus a directory
//! listing: artifact names, the spec's ordering and identity rules, the reserved
//! names, and closed shapes. Nothing here needs a closure to be legal.

mod support;

use fmp_definition::error::BuildError;
use fmp_definition::{Lock, SealedBundle, Spec};
use fmp_model::canonical::canonical_bytes;
use fmp_model::json::Json;
use support::*;

fn with_extra(value: &Json, field: &str, extra: Json) -> Json {
    match value {
        Json::Object(entries) => {
            let mut entries = entries.clone();
            entries.push((field.to_string(), extra));
            Json::Object(entries)
        }
        other => other.clone(),
    }
}

/// `a_cross_package_path_alias_is_rejected` — the same repository-relative path
/// listed twice is a `path-lexical` finding, and it is reported before the
/// ordering and version rules that would also notice the repetition.
#[test]
fn a_cross_package_path_alias_is_rejected() {
    let entry = entry_with_dummy_digest(
        "monasm.x86.example",
        "0.1.0",
        "packages/x86_64/monasm.x86.example/0.1.0",
    );
    let spec = SpecFixture::for_packages(vec![entry.clone(), entry]);
    let error = parse_spec(&spec).expect_err("a repeated path is not two packages");
    assert_eq!(error.code(), "path-lexical");
    assert!(error.to_string().contains("fold"), "{error}");
}

/// `the_artifact_filename_matches_its_bundle_id` — every one of the four
/// artifacts is named after the `bundle_id` inside it, and a mismatch is a
/// rejection rather than a rename.
#[test]
fn the_artifact_filename_matches_its_bundle_id() {
    let tree = TempTree::new("artifact-name");
    let fixture = ManifestFixture::default();
    write_release_package(&tree, &fixture);
    let spec_fixture = SpecFixture::for_packages(vec![SpecEntryFixture::of(&tree, &fixture)]);
    let bundle = checked(&tree, &spec_fixture);

    // The correctly named spec loads; the same bytes under another name do not.
    let relative = spec_fixture.write(&tree);
    Spec::load(tree.root(), &relative).expect("the artifact name matches the bundle_id");
    tree.write("bundles/specs/other.json", &spec_bytes(&spec_fixture));
    let error = Spec::load(tree.root(), "bundles/specs/other.json")
        .expect_err("a spec file name is not free");
    assert_eq!(error.code(), "bundle-file-mismatch");

    tree.write(
        "bundles/locks/other.lock.json",
        &canonical_bytes(&bundle.lock_json()),
    );
    let error = Lock::load(tree.root(), "bundles/locks/other.lock.json")
        .expect_err("a lock file name is not free");
    assert_eq!(error.code(), "bundle-file-mismatch");

    tree.write(
        "bundles/sealed/other.bundle.json",
        &canonical_bytes(&bundle.bundle_json()),
    );
    let error = SealedBundle::load(tree.root(), "bundles/sealed/other.bundle.json")
        .expect_err("a sealed file name is not free");
    assert_eq!(error.code(), "bundle-file-mismatch");

    let bundle_id = spec_fixture.bundle_id.clone();
    fmp_definition::artifact::check_legacy(
        &format!("bundles/legacy/{bundle_id}/definition.json"),
        &bundle_id,
    )
    .expect("the legacy snapshot directory names the bundle");
    let error =
        fmp_definition::artifact::check_legacy("bundles/legacy/other/definition.json", &bundle_id)
            .expect_err("a legacy snapshot directory is not free");
    assert_eq!(error.code(), "bundle-file-mismatch");
}

/// `an_unsorted_spec_is_rejected` — a reversed package list is a deterministic
/// shape rejection; the builder never re-sorts an alternate spelling.
#[test]
fn an_unsorted_spec_is_rejected() {
    let later = entry_with_dummy_digest(
        "monasm.x86.mov-register",
        "0.1.0",
        "packages/x86_64/monasm.x86.mov-register/0.1.0",
    );
    let earlier = entry_with_dummy_digest(
        "monasm.x86.add-imm",
        "0.1.0",
        "packages/x86_64/monasm.x86.add-imm/0.1.0",
    );
    // `add-imm` sorts before `mov-register`; listing them the other way round is
    // a different document that must not be silently sorted into legality.
    let spec = SpecFixture::for_packages(vec![later, earlier]);
    let error = parse_spec(&spec).expect_err("a reversed list is not the canonical one");
    match &error {
        BuildError::DocumentShape { reason, .. } => {
            assert!(reason.contains("strictly sorted"), "{reason}");
        }
        other => panic!("expected a shape rejection, got {other:?}"),
    }
}

/// `two_versions_of_one_package_id_conflict` — a package identity names one
/// version per closure, even when the two versions export disjoint rows.
#[test]
fn two_versions_of_one_package_id_conflict() {
    let spec = SpecFixture::for_packages(vec![
        entry_with_dummy_digest(
            "monasm.x86.mov-register",
            "0.1.0",
            "packages/x86_64/monasm.x86.mov-register/0.1.0",
        ),
        entry_with_dummy_digest(
            "monasm.x86.mov-register",
            "0.2.0",
            "packages/x86_64/monasm.x86.mov-register/0.2.0",
        ),
    ]);
    let error = parse_spec(&spec).expect_err("one package id cannot name two versions");
    assert_eq!(error.code(), "version-conflict");
}

/// `a_standalone_identity_cannot_be_written_into_a_spec` — the `verify
/// --package` development identity is reserved by prefix, and the prefix check
/// runs before the version grammar so the reader is told "reserved", not "bad
/// version".
#[test]
fn a_standalone_identity_cannot_be_written_into_a_spec() {
    let mut namespace = SpecFixture::for_packages(vec![entry_with_dummy_digest(
        "monasm.x86.example",
        "0.1.0",
        "packages/x86_64/monasm.x86.example/0.1.0",
    )]);
    namespace.namespace = "monasm.standalone.monasm.x86.example".to_string();
    let error = parse_spec(&namespace).expect_err("a standalone namespace is reserved");
    assert_eq!(error.code(), "reserved-identity");

    let mut version = namespace.clone();
    version.namespace = "monasm.isa.x86".to_string();
    version.version = "standalone+0123abcd".to_string();
    let error = parse_spec(&version).expect_err("a standalone version is reserved");
    assert_eq!(error.code(), "reserved-identity");
}

/// `a_frozen_legacy_definition_name_cannot_be_reused` — the pair the pinned
/// corpus already owns is read from `definitions/` in sorted path order and can
/// never name an H2 bundle; the set is read-only and is not a digest input.
#[test]
fn a_frozen_legacy_definition_name_cannot_be_reused() {
    let tree = TempTree::new("reserved-legacy");
    copy_definition(&tree, "x86_64", "0.1.0");
    let reserved = fmp_definition::spec::reserved_identities(tree.root())
        .expect("the pinned corpus is readable");
    assert!(reserved.contains(&("monasm.isa.x86".to_string(), "0.1.0".to_string())));

    let mut spec = SpecFixture::for_packages(vec![entry_with_dummy_digest(
        "monasm.x86.example",
        "0.1.0",
        "packages/x86_64/monasm.x86.example/0.1.0",
    )]);
    spec.namespace = "monasm.isa.x86".to_string();
    spec.version = "0.1.0".to_string();
    let parsed = parse_spec(&spec).expect("the pair is grammatically legal");
    let error = parsed
        .check_reserved(tree.root())
        .expect_err("a frozen definition name cannot be reused");
    assert_eq!(error.code(), "reserved-identity");

    // The reserve list is a read-time constraint only: a different identity in
    // the same tree is accepted, and nothing about `definitions/` enters a
    // digest or an artifact.
    spec.version = "0.1.0-h2".to_string();
    let parsed = parse_spec(&spec).expect("a fresh identity is legal");
    parsed
        .check_reserved(tree.root())
        .expect("only the frozen pair is reserved");
}

/// `the_spec_lock_and_sealed_shapes_are_closed` — unknown and duplicate keys are
/// rejected in all three documents, and an absent `builder.build` is an omitted
/// key rather than `null`.
#[test]
fn the_spec_lock_and_sealed_shapes_are_closed() {
    let tree = TempTree::new("closed-shapes");
    let fixture = ManifestFixture::default();
    write_release_package(&tree, &fixture);
    let spec_fixture = SpecFixture::for_packages(vec![SpecEntryFixture::of(&tree, &fixture)]);
    let bundle = checked(&tree, &spec_fixture);

    let spec_value = with_extra(&spec_fixture.json(), "sources", Json::Null);
    let error = Spec::from_json(spec_value).expect_err("a spec has no extra keys");
    assert_eq!(error.code(), "document-shape");
    let error = Spec::parse(br#"{"bundle_format":"a","bundle_format":"b"}"#)
        .expect_err("a duplicate key is not last-wins");
    assert_eq!(error.code(), "document-shape");

    let lock_value = bundle.lock_json();
    let error = Lock::from_json(with_extra(&lock_value, "path", Json::Null))
        .expect_err("a lock has no extra keys");
    assert_eq!(error.code(), "document-shape");
    let error =
        Lock::from_json(json_without(&lock_value, "builder")).expect_err("builder is required");
    assert_eq!(error.code(), "document-shape");
    let error = Lock::parse(br#"{"lock_format":"a","lock_format":"b"}"#)
        .expect_err("a duplicate key is not last-wins");
    assert_eq!(error.code(), "document-shape");

    let builder = match &lock_value {
        Json::Object(entries) => entries
            .iter()
            .find(|(key, _)| key == "builder")
            .map(|(_, value)| value.clone())
            .expect("the lock carries builder"),
        other => panic!("not a lock object: {other:?}"),
    };
    match &builder {
        Json::Object(entries) => {
            assert!(
                entries.iter().all(|(key, _)| key != "build"),
                "an absent build id is omitted, never null: {entries:?}"
            );
        }
        other => panic!("builder is not an object: {other:?}"),
    }

    let sealed_value = bundle.bundle_json();
    let error = SealedBundle::from_json(with_extra(&sealed_value, "sources", Json::Null))
        .expect_err("a sealed bundle has no sources key");
    assert_eq!(error.code(), "document-shape");
    let error = SealedBundle::parse(br#"{"bundle_id":"a","bundle_id":"b"}"#)
        .expect_err("a duplicate key is not last-wins");
    assert_eq!(error.code(), "document-shape");

    // The same build with a named build identifier writes the key.
    let parsed = parse_spec(&spec_fixture).expect("the spec parses");
    let named = fmp_definition::CheckedBundle::build(
        tree.root(),
        &parsed,
        fmp_definition::Builder::default().with_build("deadbeef"),
    )
    .expect("the bundle builds");
    match &named.lock_json() {
        Json::Object(entries) => {
            let builder = entries
                .iter()
                .find(|(key, _)| key == "builder")
                .map(|(_, value)| value)
                .expect("the lock carries builder");
            match builder {
                Json::Object(fields) => assert!(
                    fields
                        .iter()
                        .any(|(key, value)| key == "build" && value.as_str() == Some("deadbeef")),
                    "a present build id is written: {fields:?}"
                ),
                other => panic!("builder is not an object: {other:?}"),
            }
        }
        other => panic!("not a lock object: {other:?}"),
    }
}
