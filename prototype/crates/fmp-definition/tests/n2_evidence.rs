//! Evidence and release identity: what changes `evidence_digest`,
//! `release_digest` and `definition_digest`, and what does not (`ADR-0128` §7,
//! §7.1, §8.2).

mod support;

use support::*;

fn rewrite_manifest(tree: &TempTree, fixture: &ManifestFixture, status: &str) {
    let relative = package_relative(fixture);
    let files = vec![
        ("NOTICE".to_string(), raw_sha256(DEFAULT_NOTICE.as_bytes())),
        (
            "tests/cases.json".to_string(),
            raw_sha256(DEFAULT_CASES.as_bytes()),
        ),
    ];
    tree.write(
        &format!("{relative}/evidence/manifest.json"),
        evidence_manifest(&files, status).as_bytes(),
    );
}

/// `the_case_file_is_part_of_the_release_digest` — replacing `tests/cases.json`
/// and updating its hash changes the evidence and release digests, and leaves
/// the execution rules untouched.
#[test]
fn the_case_file_is_part_of_the_release_digest() {
    let tree = TempTree::new("cases-release");
    let fixture = ManifestFixture::default();
    let relative = write_release_package(&tree, &fixture);
    let spec = SpecFixture::for_packages(vec![SpecEntryFixture::of(&tree, &fixture)]);

    let first = checked(&tree, &spec);
    let definition = first.definition_digest().to_string();
    let evidence = first.closure().packages()[0]
        .evidence_digest()
        .expect("a release-ready package has evidence");
    let release = first.release_digest().to_string();

    let cases =
        "{\"cases\":[{\"case_id\":\"x86-example-pos\"}],\"cases_format\":\"monasm-cases/0.1\"}\n";
    tree.write(&format!("{relative}/tests/cases.json"), cases.as_bytes());
    let files = vec![
        ("NOTICE".to_string(), raw_sha256(DEFAULT_NOTICE.as_bytes())),
        ("tests/cases.json".to_string(), raw_sha256(cases.as_bytes())),
    ];
    tree.write(
        &format!("{relative}/evidence/manifest.json"),
        evidence_manifest(&files, "manual-derivation").as_bytes(),
    );

    let second = checked(&tree, &spec);
    assert_eq!(second.definition_digest(), definition);
    assert_ne!(
        second.closure().packages()[0].evidence_digest().as_deref(),
        Some(evidence.as_str())
    );
    assert_ne!(second.release_digest(), release);
}

/// `evidence_changes_do_not_move_the_definition_digest` — an evidence file that
/// is not an execution input moves only the evidence and release layers.
#[test]
fn evidence_changes_do_not_move_the_definition_digest() {
    let tree = TempTree::new("evidence-layers");
    let fixture = ManifestFixture::default();

    write_release_package_with(
        &tree,
        &fixture,
        DEFAULT_CASES.as_bytes(),
        &[("evidence/legacy-source.md", b"x86_64/0.1.0 rows\n")],
    );
    let spec = SpecFixture::for_packages(vec![SpecEntryFixture::of(&tree, &fixture)]);
    let first = checked(&tree, &spec);

    write_release_package_with(
        &tree,
        &fixture,
        DEFAULT_CASES.as_bytes(),
        &[(
            "evidence/legacy-source.md",
            b"x86_64/0.1.0 rows, extended\n",
        )],
    );
    let second = checked(&tree, &spec);

    assert_eq!(first.definition_digest(), second.definition_digest());
    assert_eq!(first.bundle_digest(), second.bundle_digest());
    assert_ne!(
        first.closure().packages()[0].evidence_digest(),
        second.closure().packages()[0].evidence_digest()
    );
    assert_ne!(first.release_digest(), second.release_digest());
}

/// `release_digest_tracks_the_release_not_the_builder` — the builder identity is
/// not in the release preimage, so two builder versions agree; two evidence
/// snapshots do not.
#[test]
fn release_digest_tracks_the_release_not_the_builder() {
    let tree = TempTree::new("builder-release");
    let fixture = ManifestFixture::default();
    write_release_package(&tree, &fixture);
    let spec = SpecFixture::for_packages(vec![SpecEntryFixture::of(&tree, &fixture)]);
    let parsed = parse_spec(&spec).expect("the spec parses");

    let one = fmp_definition::CheckedBundle::build(
        tree.root(),
        &parsed,
        fmp_definition::Builder::new("fmp-definition", "0.0.0"),
    )
    .expect("the first builder builds");
    let two = fmp_definition::CheckedBundle::build(
        tree.root(),
        &parsed,
        fmp_definition::Builder::new("fmp-definition", "9.9.9").with_build("other"),
    )
    .expect("the second builder builds");

    assert_eq!(one.definition_digest(), two.definition_digest());
    assert_eq!(one.bundle_digest(), two.bundle_digest());
    assert_eq!(one.release_digest(), two.release_digest());
    assert_ne!(
        canonical_builder(&one.lock_json()),
        canonical_builder(&two.lock_json())
    );

    // A different evidence snapshot is a different release under the same
    // builder identity.
    rewrite_manifest(&tree, &fixture, "reproduced");
    let three = fmp_definition::CheckedBundle::build(
        tree.root(),
        &parsed,
        fmp_definition::Builder::new("fmp-definition", "0.0.0"),
    )
    .expect("the third build succeeds");
    assert_eq!(one.definition_digest(), three.definition_digest());
    assert_ne!(one.release_digest(), three.release_digest());
}

fn canonical_builder(lock: &fmp_model::json::Json) -> Vec<u8> {
    let builder = lock
        .get("builder")
        .expect("the lock carries builder")
        .clone();
    fmp_model::canonical::canonical_bytes(&builder)
}

/// `editing_cases_json_changes_the_release_identity` — the merged definition
/// bytes and `definition_digest` stay fixed while the release identity moves.
#[test]
fn editing_cases_json_changes_the_release_identity() {
    let tree = TempTree::new("cases-identity");
    let fixture = ManifestFixture::default();
    write_release_package(&tree, &fixture);
    let spec = SpecFixture::for_packages(vec![SpecEntryFixture::of(&tree, &fixture)]);
    let first = checked(&tree, &spec);
    let definition_bytes =
        fmp_model::canonical::canonical_bytes(first.closure().definition_value());

    let cases = "{\"cases\":[{\"case_id\":\"x86-other\"}],\"cases_format\":\"monasm-cases/0.1\"}\n";
    write_release_package_with(&tree, &fixture, cases.as_bytes(), &[]);
    let second = checked(&tree, &spec);

    assert_eq!(
        definition_bytes,
        fmp_model::canonical::canonical_bytes(second.closure().definition_value())
    );
    assert_eq!(first.definition_digest(), second.definition_digest());
    assert_ne!(
        first.closure().packages()[0].evidence_digest(),
        second.closure().packages()[0].evidence_digest()
    );
    assert_ne!(first.release_digest(), second.release_digest());
}

/// `evidence_digest_tracks_case_evidence` — an evidence-manifest edit that
/// changes no file hash still changes `evidence_digest` and `release_digest`.
#[test]
fn evidence_digest_tracks_case_evidence() {
    let tree = TempTree::new("evidence-manifest-edit");
    let fixture = ManifestFixture::default();
    write_release_package(&tree, &fixture);
    let spec = SpecFixture::for_packages(vec![SpecEntryFixture::of(&tree, &fixture)]);
    let first = checked(&tree, &spec);

    rewrite_manifest(&tree, &fixture, "reproduced");
    let second = checked(&tree, &spec);

    assert_eq!(first.definition_digest(), second.definition_digest());
    assert_eq!(first.bundle_digest(), second.bundle_digest());
    assert_ne!(
        first.closure().packages()[0].evidence_digest(),
        second.closure().packages()[0].evidence_digest()
    );
    assert_ne!(first.release_digest(), second.release_digest());
}
