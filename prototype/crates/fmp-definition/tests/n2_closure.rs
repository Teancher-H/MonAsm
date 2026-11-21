//! The explicit closure (`ADR-0128` §4, §4.1, §5, §9): ordering, dependency
//! edges, ownership, the target cover and the merge.
//!
//! Every closure here selects release-ready packages, because a lock exists only
//! for a release-ready closure (§7.1). A row that needs a rejection checks the
//! rejection's own class, not the evidence layer that follows it.

mod support;

use std::path::Path;

use fmp_definition::error::BuildError;
use fmp_definition::LoadedPackage;
use fmp_model::canonical::canonical_bytes;
use fmp_model::json::Json;
use support::*;

const FIELD: &str = "field-placement/v1";
const INTEGER: &str = "integer-domain/v1";
const MOV_R64: &str = "x86:mov/r64-rm/legacy";
const MOV_RM: &str = "x86:mov/rm-r64/legacy";
const ADD: &str = "x86:add/rm64-imm8/legacy";
const RIPREL: &str = "x86:mov/r64-riprel32/legacy";

fn mov_fixture() -> ManifestFixture {
    ManifestFixture::default()
}

fn add_fixture() -> ManifestFixture {
    package_with(
        "monasm.x86.add-imm",
        &[(ADD, "forms/add.json")],
        &[FIELD, INTEGER],
    )
}

fn mov_r64_fixture() -> ManifestFixture {
    package_with(
        "monasm.x86.mov-r64",
        &[(MOV_R64, "forms/mov-r64.json")],
        &[FIELD],
    )
}

fn mov_rm_fixture() -> ManifestFixture {
    package_with(
        "monasm.x86.mov-rm",
        &[(MOV_RM, "forms/mov-rm.json")],
        &[FIELD],
    )
}

/// A `fmp-def/0.2` package whose one form is the riprel row.
fn v2_fixture(package_id: &str, path: &str, extensions: &[&str]) -> ManifestFixture {
    ManifestFixture {
        package_id: package_id.to_string(),
        version: "0.1.0".to_string(),
        definition_format: "fmp-def/0.2".to_string(),
        forms: vec![(RIPREL.to_string(), path.to_string())],
        capabilities: vec![FIELD.to_string(), INTEGER.to_string()],
        extensions: extensions.iter().map(|name| (*name).to_string()).collect(),
        legacy: None,
        ..ManifestFixture::default()
    }
}

fn spec_of(tree: &TempTree, fixtures: &[&ManifestFixture]) -> SpecFixture {
    let mut entries: Vec<SpecEntryFixture> = fixtures
        .iter()
        .map(|fixture| SpecEntryFixture::of(tree, fixture))
        .collect();
    entries.sort_by(|left, right| {
        (&left.package_id, &left.version).cmp(&(&right.package_id, &right.version))
    });
    SpecFixture::for_packages(entries)
}

fn v2_spec_of(tree: &TempTree, fixture: &ManifestFixture, extensions: &[&str]) -> SpecFixture {
    let mut spec = spec_of(tree, &[fixture]);
    spec.definition_format = "fmp-def/0.2".to_string();
    spec.extensions = extensions.iter().map(|name| (*name).to_string()).collect();
    spec
}

fn dir_bytes(path: &Path) -> u64 {
    let mut total = 0;
    for entry in std::fs::read_dir(path).expect("read the package directory") {
        let entry = entry.expect("read a directory entry");
        let metadata = entry.metadata().expect("read the entry metadata");
        if metadata.is_dir() {
            total += dir_bytes(&entry.path());
        } else {
            total += metadata.len();
        }
    }
    total
}

/// `the_same_relative_path_in_two_packages_is_legal` — the conflict domain is the
/// package root, so two packages may each own a `forms/add.json`; a repository
/// path collision is a different question.
#[test]
fn the_same_relative_path_in_two_packages_is_legal() {
    let tree = TempTree::new("same-relative-path");
    let a = package_with(
        "monasm.x86.mov-r64",
        &[(MOV_R64, "forms/add.json")],
        &[FIELD],
    );
    let b = package_with(
        "monasm.x86.add-imm",
        &[(ADD, "forms/add.json")],
        &[FIELD, INTEGER],
    );
    write_release_package(&tree, &a);
    write_release_package(&tree, &b);

    let spec = spec_of(&tree, &[&a, &b]);
    let bundle = checked(&tree, &spec);
    let sealed = bundle.bundle_json();
    assert_eq!(
        sealed
            .get("packages")
            .and_then(Json::as_array)
            .map(<[Json]>::len),
        Some(2)
    );
    assert_eq!(
        sealed
            .get("form_owners")
            .and_then(Json::as_array)
            .map(<[Json]>::len),
        Some(2)
    );
}

/// `the_same_inputs_build_to_the_same_bundle_digest` — two builds in two
/// directories name the same bundle.
#[test]
fn the_same_inputs_build_to_the_same_bundle_digest() {
    let a = mov_fixture();
    let b = add_fixture();

    let first = TempTree::new("same-inputs-a");
    write_release_package(&first, &a);
    write_release_package(&first, &b);
    let first_bundle = checked(&first, &spec_of(&first, &[&a, &b]));

    let second = TempTree::new("same-inputs-b");
    write_release_package(&second, &a);
    write_release_package(&second, &b);
    let second_bundle = checked(&second, &spec_of(&second, &[&a, &b]));

    assert_eq!(first_bundle.bundle_digest(), second_bundle.bundle_digest());
    assert_eq!(
        canonical_bytes(&first_bundle.bundle_json()),
        canonical_bytes(&second_bundle.bundle_json())
    );
}

/// `package_discovery_order_does_not_change_the_bundle` — directory creation
/// order and stray directories are not inputs.
#[test]
fn package_discovery_order_does_not_change_the_bundle() {
    let a = mov_fixture();
    let b = add_fixture();

    let first = TempTree::new("discovery-only-a");
    std::fs::create_dir_all(first.root().join("packages/x86_64/zzz-empty")).expect("a stray dir");
    write_release_package(&first, &a);
    write_release_package(&first, &b);
    let first_bundle = checked(&first, &spec_of(&first, &[&a, &b]));

    let second = TempTree::new("discovery-only-b");
    write_release_package(&second, &b);
    std::fs::create_dir_all(second.root().join("packages/x86_64/aaa-empty")).expect("a stray dir");
    write_release_package(&second, &a);
    let second_bundle = checked(&second, &spec_of(&second, &[&a, &b]));

    assert_eq!(
        canonical_bytes(&first_bundle.bundle_json()),
        canonical_bytes(&second_bundle.bundle_json())
    );
}

/// `an_unselected_package_does_not_change_an_old_bundle` — even a corrupt package
/// directory that the spec does not list is invisible.
#[test]
fn an_unselected_package_does_not_change_an_old_bundle() {
    let tree = TempTree::new("unselected-package");
    let a = mov_fixture();
    write_release_package(&tree, &a);
    let spec = spec_of(&tree, &[&a]);
    let before = checked(&tree, &spec);

    tree.write(
        "packages/x86_64/monasm.x86.broken/9.9.9/package.json",
        b"{ this is not json",
    );
    let after = checked(&tree, &spec);

    assert_eq!(
        canonical_bytes(&before.bundle_json()),
        canonical_bytes(&after.bundle_json())
    );
    assert_eq!(
        canonical_bytes(&before.lock_json()),
        canonical_bytes(&after.lock_json())
    );
}

/// `a_dependency_outside_the_spec_is_refused` — the closure is explicit; an edge
/// to a package that is not listed is a rejection, not a directory scan.
#[test]
fn a_dependency_outside_the_spec_is_refused() {
    let tree = TempTree::new("dependency-outside");
    let b = add_fixture();
    write_release_package(&tree, &b);
    let mut a = mov_fixture();
    a.dependencies = vec![(
        b.package_id.clone(),
        b.version.clone(),
        package_digest(&tree, &b),
    )];
    write_release_package(&tree, &a);

    let spec = spec_of(&tree, &[&a]);
    let error = build_bundle(&tree, &spec).expect_err("the edge leaves the closure");
    match error {
        BuildError::DependencyMismatch { reason, .. } => {
            assert!(reason.contains("not listed"), "{reason}");
        }
        other => panic!("expected a dependency rejection, got {other:?}"),
    }
}

/// `the_spec_lists_every_package_in_the_closure` — removing a depended-on entry
/// is the same rejection, and listing it again restores the closure.
#[test]
fn the_spec_lists_every_package_in_the_closure() {
    let tree = TempTree::new("closure-complete");
    let b = add_fixture();
    write_release_package(&tree, &b);
    let mut a = mov_fixture();
    a.dependencies = vec![(
        b.package_id.clone(),
        b.version.clone(),
        package_digest(&tree, &b),
    )];
    write_release_package(&tree, &a);

    let complete = spec_of(&tree, &[&a, &b]);
    checked(&tree, &complete);

    let missing = spec_of(&tree, &[&a]);
    let error = build_bundle(&tree, &missing).expect_err("a removed entry breaks the closure");
    assert_eq!(error.code(), "dependency-mismatch");
}

/// `a_dependency_must_match_its_exact_digest` — presence is not enough; the edge
/// names the source snapshot it was resolved against.
#[test]
fn a_dependency_must_match_its_exact_digest() {
    let tree = TempTree::new("dependency-digest");
    let b = add_fixture();
    write_release_package(&tree, &b);
    let mut a = mov_fixture();
    a.dependencies = vec![(
        b.package_id.clone(),
        b.version.clone(),
        format!("sha256:{}", "0".repeat(64)),
    )];
    write_release_package(&tree, &a);

    let error = build_bundle(&tree, &spec_of(&tree, &[&a, &b]))
        .expect_err("a mismatched source digest is not this dependency");
    assert_eq!(error.code(), "dependency-mismatch");
    assert!(error.to_string().contains("digest"), "{error}");
}

/// `a_dependency_cycle_is_refused` — A→B→A is named as a cycle rather than
/// recursing or reaching a digest comparison.
#[test]
fn a_dependency_cycle_is_refused() {
    let tree = TempTree::new("dependency-cycle");
    let a = package_with(
        "monasm.x86.cycle-a",
        &[(MOV_R64, "forms/mov-r64.json")],
        &[FIELD],
    );
    let b = package_with(
        "monasm.x86.cycle-b",
        &[(MOV_RM, "forms/mov-rm.json")],
        &[FIELD],
    );
    let dummy = format!("sha256:{}", "0".repeat(64));
    let mut a_manifest = a.clone();
    a_manifest.dependencies = vec![(b.package_id.clone(), b.version.clone(), dummy.clone())];
    let mut b_manifest = b.clone();
    b_manifest.dependencies = vec![(a.package_id.clone(), a.version.clone(), dummy)];

    write_release_package(&tree, &a_manifest);
    write_release_package(&tree, &b_manifest);

    let error = build_bundle(&tree, &spec_of(&tree, &[&a_manifest, &b_manifest]))
        .expect_err("a cycle is not a closure");
    match error {
        BuildError::DependencyMismatch { reason, .. } => {
            assert!(reason.contains("cycle"), "{reason}");
        }
        other => panic!("expected a cycle rejection, got {other:?}"),
    }
}

/// `the_same_dependency_reached_twice_is_loaded_once` — a diamond lists the
/// shared package once, both edges are checked, and its bytes are charged once.
#[test]
fn the_same_dependency_reached_twice_is_loaded_once() {
    let tree = TempTree::new("dependency-diamond");
    let shared = add_fixture();
    write_release_package(&tree, &shared);
    let shared_digest = package_digest(&tree, &shared);

    let mut a = mov_r64_fixture();
    a.dependencies = vec![(
        shared.package_id.clone(),
        shared.version.clone(),
        shared_digest.clone(),
    )];
    let mut b = mov_rm_fixture();
    b.dependencies = vec![(
        shared.package_id.clone(),
        shared.version.clone(),
        shared_digest,
    )];
    write_release_package(&tree, &a);
    write_release_package(&tree, &b);

    let spec = spec_of(&tree, &[&a, &b, &shared]);
    let bundle = checked(&tree, &spec);
    assert_eq!(bundle.closure().packages().len(), 3);
    assert_eq!(bundle.closure().form_owners().len(), 3);
    assert_eq!(
        bundle
            .bundle_json()
            .get("packages")
            .and_then(Json::as_array)
            .map(<[Json]>::len),
        Some(3),
        "the shared package is listed once"
    );

    let expected: u64 = [&a, &b, &shared]
        .iter()
        .map(|fixture| dir_bytes(&tree.root().join(package_relative(fixture))))
        .sum();
    assert_eq!(
        bundle.closure().package_root_bytes(),
        expected,
        "a shared package is charged once, not once per edge"
    );
}

/// `two_packages_exporting_the_same_form_conflict` — identical content is still a
/// conflict, and it is reported before the merge.
#[test]
fn two_packages_exporting_the_same_form_conflict() {
    let tree = TempTree::new("owner-conflict");
    let a = package_with(
        "monasm.x86.owner-a",
        &[(MOV_R64, "forms/mov.json")],
        &[FIELD],
    );
    let b = package_with(
        "monasm.x86.owner-b",
        &[(MOV_R64, "forms/mov.json")],
        &[FIELD],
    );
    write_release_package(&tree, &a);
    write_release_package(&tree, &b);

    let error = build_bundle(&tree, &spec_of(&tree, &[&a, &b]))
        .expect_err("one form cannot have two owners");
    assert_eq!(error.code(), "owner-conflict");
    match error {
        BuildError::OwnerConflict { form_id, .. } => assert_eq!(form_id, MOV_R64),
        other => panic!("expected an ownership conflict, got {other:?}"),
    }
}

/// `a_file_form_id_must_match_its_export` — the declaration is a claim; the file
/// carries the fact.
#[test]
fn a_file_form_id_must_match_its_export() {
    let tree = TempTree::new("form-id-swap");
    let fixture = mov_fixture();
    let relative = write_release_package(&tree, &fixture);

    // Swap the two rows on disk while leaving the manifest untouched.
    tree.write(
        &format!("{relative}/forms/mov-r64-rm.json"),
        row_for(MOV_RM).as_bytes(),
    );
    tree.write(
        &format!("{relative}/forms/mov-rm-r64.json"),
        row_for(MOV_R64).as_bytes(),
    );

    let error = LoadedPackage::load(tree.root(), &relative)
        .expect_err("the file's own form_id is the ownership fact");
    match error {
        BuildError::DocumentShape { reason, .. } => {
            assert!(
                reason.contains("differs from the declared export"),
                "{reason}"
            );
        }
        other => panic!("expected a shape rejection, got {other:?}"),
    }
}

/// `two_packages_with_equal_target_identity_and_distinct_profile_labels_can_compose`
/// — the label is descriptive; one structural identity field decides.
#[test]
fn two_packages_with_equal_target_identity_and_distinct_profile_labels_can_compose() {
    let tree = TempTree::new("profile-label");
    let a = mov_r64_fixture();
    let mut b = mov_rm_fixture();
    b.target_profile = "monasm.target.x86_64.alt".to_string();
    write_release_package(&tree, &a);
    write_release_package(&tree, &b);
    checked(&tree, &spec_of(&tree, &[&a, &b]));

    let mut changed = b.clone();
    changed.isa_variant = "x86-32".to_string();
    write_release_package_value(
        &tree,
        &changed,
        &changed.json(),
        DEFAULT_CASES.as_bytes(),
        &[],
    );

    let error = build_bundle(&tree, &spec_of(&tree, &[&a, &changed]))
        .expect_err("a structural identity field is not a label");
    match error {
        BuildError::TargetMismatch { field, .. } => assert_eq!(field, "isa_variant"),
        other => panic!("expected a target mismatch, got {other:?}"),
    }
}

/// `a_form_family_must_match_the_package_target` — equality with the declared
/// family, reported before any asset is read.
#[test]
fn a_form_family_must_match_the_package_target() {
    let tree = TempTree::new("form-family");
    let mut fixture = mov_r64_fixture();
    fixture.isa_family = "aarch64".to_string();
    fixture.target_dir = "aarch64".to_string();
    write_release_package(&tree, &fixture);

    let error = LoadedPackage::load(tree.root(), &package_relative(&fixture))
        .expect_err("an aarch64 package cannot export an x86 row");
    assert_eq!(error.code(), "form-family-mismatch");
    match error {
        BuildError::FormFamilyMismatch {
            form_id,
            family,
            target,
        } => {
            assert_eq!(form_id, MOV_R64);
            assert_eq!(family, "x86");
            assert_eq!(target, "aarch64");
        }
        other => panic!("expected a family mismatch, got {other:?}"),
    }
}

/// `the_family_rule_is_equality_not_a_package_whitelist` — an unknown family
/// passes the package layer and is rejected by `fmp_model::definition::read`.
#[test]
fn the_family_rule_is_equality_not_a_package_whitelist() {
    let tree = TempTree::new("family-equality");
    let fixture = ManifestFixture {
        package_id: "monasm.la.add".to_string(),
        forms: vec![(
            "loongarch:add/legacy".to_string(),
            "forms/add.json".to_string(),
        )],
        capabilities: Vec::new(),
        legacy: None,
        isa_family: "loongarch".to_string(),
        isa_variant: "la64".to_string(),
        target_dir: "loongarch".to_string(),
        ..ManifestFixture::default()
    };
    write_release_package(&tree, &fixture);
    overwrite_row(
        &tree,
        &fixture,
        "forms/add.json",
        &json_of(r#"{"form_id":"loongarch:add/legacy","template":"90"}"#),
    );

    LoadedPackage::load(tree.root(), &package_relative(&fixture))
        .expect("the package layer demands equality, not a known family");

    let mut spec = spec_of(&tree, &[&fixture]);
    spec.isa_family = "loongarch".to_string();
    spec.isa_variant = "la64".to_string();
    let error = build_bundle(&tree, &spec).expect_err("the reader is the only family authority");
    assert_eq!(error.code(), "definition-rejected");
    assert!(error.to_string().contains("unknown ISA family"), "{error}");
}

/// `a_package_cover_is_a_subset_of_the_bundle_target` — `⋃E_form ⊆ E_package ⊆
/// E_bundle`; a member the bundle does not select makes the package illegal.
#[test]
fn a_package_cover_is_a_subset_of_the_bundle_target() {
    let tree = TempTree::new("cover-subset");
    let fixture = v2_fixture("monasm.x86.v2", "forms/mov.json", &["sse2"]);
    write_release_package(&tree, &fixture);

    checked(&tree, &v2_spec_of(&tree, &fixture, &["sse2"]));

    let error = build_bundle(&tree, &v2_spec_of(&tree, &fixture, &[]))
        .expect_err("a cover member the bundle does not select is illegal");
    match error {
        BuildError::TargetMismatch { field, .. } => assert_eq!(field, "enabled_extensions"),
        other => panic!("expected a cover rejection, got {other:?}"),
    }
}

/// `a_form_requirement_must_be_inside_its_own_package` — checked per form, before
/// the bundle's selection can rescue it.
#[test]
fn a_form_requirement_must_be_inside_its_own_package() {
    let tree = TempTree::new("form-requirement");
    let fixture = v2_fixture("monasm.x86.v2", "forms/mov.json", &[]);
    write_release_package(&tree, &fixture);
    let mut row = json_of(row_for(RIPREL));
    row = json_set(
        &row,
        "requires_extensions",
        Json::Array(vec![Json::Str("avx".to_string())]),
    );
    overwrite_row(&tree, &fixture, "forms/mov.json", &row);

    let error = build_bundle(&tree, &v2_spec_of(&tree, &fixture, &["avx"]))
        .expect_err("the bundle selection is not the package cover");
    assert_eq!(error.code(), "form-extension-mismatch");
}

/// `an_over_declared_extension_cover_is_legal_but_narrower` — a cover larger than
/// the forms need is legal and is copied unchanged; a narrower bundle fails.
#[test]
fn an_over_declared_extension_cover_is_legal_but_narrower() {
    let tree = TempTree::new("over-declared-cover");
    let fixture = v2_fixture("monasm.x86.v2", "forms/mov.json", &["avx", "sse2"]);
    write_release_package(&tree, &fixture);

    let bundle = checked(&tree, &v2_spec_of(&tree, &fixture, &["avx", "sse2"]));
    let entry = bundle
        .bundle_json()
        .get("packages")
        .and_then(Json::as_array)
        .and_then(|items| items.first())
        .cloned()
        .expect("one package entry");
    let cover: Vec<&str> = entry
        .get("enabled_extensions")
        .and_then(Json::as_array)
        .expect("the cover is copied")
        .iter()
        .map(|name| name.as_str().expect("extension names are strings"))
        .collect();
    assert_eq!(cover, ["avx", "sse2"], "the cover is never trimmed");

    let error = build_bundle(&tree, &v2_spec_of(&tree, &fixture, &["avx"]))
        .expect_err("a bundle narrower than the cover is illegal");
    assert_eq!(error.code(), "target-mismatch");
}

/// `fmp_def_0_1_keeps_the_transitional_exact_target` — under `0.1` the cover must
/// equal the selection, so even a legal subset is rejected.
#[test]
fn fmp_def_0_1_keeps_the_transitional_exact_target() {
    let tree = TempTree::new("exact-target");
    let mut fixture = mov_r64_fixture();
    fixture.extensions = vec!["avx".to_string()];
    write_release_package(&tree, &fixture);

    let mut exact = spec_of(&tree, &[&fixture]);
    exact.extensions = vec!["avx".to_string()];
    checked(&tree, &exact);

    let mut wider = spec_of(&tree, &[&fixture]);
    wider.extensions = vec!["avx".to_string(), "sse2".to_string()];
    let error =
        build_bundle(&tree, &wider).expect_err("0.1 keeps the exact-target rule even for a subset");
    assert_eq!(error.code(), "h2-exact-target");
}

/// `a_profile_id_is_not_a_global_target_identity` — two bundles may share a label
/// and select different extension sets; H2 adds no cross-spec uniqueness rule.
#[test]
fn a_profile_id_is_not_a_global_target_identity() {
    let tree = TempTree::new("profile-not-identity");
    let a = v2_fixture("monasm.x86.v2-a", "forms/mov.json", &["sse2"]);
    let b = v2_fixture("monasm.x86.v2-b", "forms/mov.json", &["avx"]);
    write_release_package(&tree, &a);
    write_release_package(&tree, &b);

    let mut spec_a = v2_spec_of(&tree, &a, &["sse2"]);
    spec_a.bundle_id = "monasm.bundle.x86.a".to_string();
    let mut spec_b = v2_spec_of(&tree, &b, &["avx"]);
    spec_b.bundle_id = "monasm.bundle.x86.b".to_string();
    spec_b.version = "0.1.1-h2".to_string();

    assert_eq!(spec_a.profile_id, spec_b.profile_id);
    checked(&tree, &spec_a);
    checked(&tree, &spec_b);

    let parsed_a = parse_spec(&spec_a).expect("spec a parses");
    let parsed_b = parse_spec(&spec_b).expect("spec b parses");
    fmp_definition::spec::check_spec_set(&[parsed_a, parsed_b])
        .expect("a shared profile label is not a shared identity");
}

/// `the_closure_budget_counts_case_and_evidence_bytes` — 12 MiB cases plus 12 MiB
/// evidence per package crosses 64 MiB on the third, and a shared package is
/// charged once.
#[test]
fn the_closure_budget_counts_case_and_evidence_bytes() {
    const TWELVE_MIB: usize = 12 * 1024 * 1024;
    let mut cases =
        String::from("{\"cases\":[],\"cases_format\":\"monasm-cases/0.1\",\"padding\":\"");
    cases.push_str(&"x".repeat(TWELVE_MIB));
    cases.push_str("\"}\n");
    let blob = vec![b'y'; TWELVE_MIB];

    let tree = TempTree::new("closure-budget");
    let fixtures = [
        package_with("monasm.x86.big-a", &[(MOV_R64, "forms/mov.json")], &[FIELD]),
        package_with("monasm.x86.big-b", &[(MOV_RM, "forms/mov.json")], &[FIELD]),
        package_with(
            "monasm.x86.big-c",
            &[(ADD, "forms/add.json")],
            &[FIELD, INTEGER],
        ),
    ];
    for fixture in &fixtures {
        write_release_package_with(
            &tree,
            fixture,
            cases.as_bytes(),
            &[("evidence/blob.bin", blob.as_slice())],
        );
    }

    let spec = spec_of(&tree, &fixtures.iter().collect::<Vec<_>>());
    let error = build_bundle(&tree, &spec).expect_err("72 MiB crosses the 64 MiB closure budget");
    match error {
        BuildError::AggregateLimit { limit } => assert_eq!(limit, 64 << 20),
        other => panic!("expected the aggregate limit, got {other:?}"),
    }

    // Charge-once: the diamond's shared package contributes its bytes once.
    let small = TempTree::new("closure-charge-once");
    let shared = add_fixture();
    write_release_package(&small, &shared);
    let shared_digest = package_digest(&small, &shared);
    let mut a = mov_r64_fixture();
    a.dependencies = vec![(
        shared.package_id.clone(),
        shared.version.clone(),
        shared_digest.clone(),
    )];
    let mut b = mov_rm_fixture();
    b.dependencies = vec![(
        shared.package_id.clone(),
        shared.version.clone(),
        shared_digest,
    )];
    write_release_package(&small, &a);
    write_release_package(&small, &b);
    let bundle = checked(&small, &spec_of(&small, &[&a, &b, &shared]));
    let expected: u64 = [&a, &b, &shared]
        .iter()
        .map(|fixture| dir_bytes(&small.root().join(package_relative(fixture))))
        .sum();
    assert_eq!(bundle.closure().package_root_bytes(), expected);
}

/// `the_generated_definition_is_read_by_fmp_model` — the builder merges and wraps
/// the reader's rejection; it does not keep a second form validator.
#[test]
fn the_generated_definition_is_read_by_fmp_model() {
    let tree = TempTree::new("reader-authority");
    let fixture = package_with(
        "monasm.x86.bad-row",
        &[("x86:bad/none/legacy", "forms/bad.json")],
        &[],
    );
    write_release_package(&tree, &fixture);
    overwrite_row(
        &tree,
        &fixture,
        "forms/bad.json",
        &json_of(r#"{"form_id":"x86:bad/none/legacy","slots":[],"template":"9"}"#),
    );
    LoadedPackage::load(tree.root(), &package_relative(&fixture))
        .expect("the package layer does not validate a template");

    let error = build_bundle(&tree, &spec_of(&tree, &[&fixture]))
        .expect_err("an odd template is the reader's finding");
    assert_eq!(error.code(), "definition-rejected");
    match error {
        BuildError::DefinitionRejected { detail } => {
            assert!(
                detail.contains("odd number of hex digits"),
                "the reader's text is preserved: {detail}"
            );
        }
        other => panic!("expected a wrapped reader rejection, got {other:?}"),
    }
}

/// `a_package_update_does_not_edit_an_old_spec` — a new version directory is a
/// new selection, not an edit to the old lock.
#[test]
fn a_package_update_does_not_edit_an_old_spec() {
    let tree = TempTree::new("package-update");
    let v1 = mov_fixture();
    write_release_package(&tree, &v1);
    let spec = spec_of(&tree, &[&v1]);
    let before = checked(&tree, &spec);
    let lock_bytes = canonical_bytes(&before.lock_json());

    let mut v2 = mov_fixture();
    v2.version = "0.2.0".to_string();
    write_release_package(&tree, &v2);

    let after = checked(&tree, &spec);
    assert_eq!(lock_bytes, canonical_bytes(&after.lock_json()));
    assert_eq!(
        canonical_bytes(&before.bundle_json()),
        canonical_bytes(&after.bundle_json())
    );
}

/// `the_package_export_set_is_exact` — a file the manifest does not declare is
/// invisible; there is no hidden form.
#[test]
fn the_package_export_set_is_exact() {
    let tree = TempTree::new("export-set");
    let fixture = mov_fixture();
    let relative = write_release_package(&tree, &fixture);
    tree.write(
        &format!("{relative}/forms/hidden.json"),
        row_for(ADD).as_bytes(),
    );

    let package = LoadedPackage::load(tree.root(), &relative).expect("load");
    assert_eq!(package.forms().len(), 2);

    let bundle = checked(&tree, &spec_of(&tree, &[&fixture]));
    let sealed = bundle.bundle_json();
    let owners = sealed
        .get("form_owners")
        .and_then(Json::as_array)
        .expect("the owner map exists");
    let ids: Vec<&str> = owners
        .iter()
        .map(|row| {
            row.get("form_id")
                .and_then(Json::as_str)
                .expect("a form id")
        })
        .collect();
    assert_eq!(ids, [MOV_R64, MOV_RM]);
    assert!(!ids.contains(&ADD), "an undeclared row is not exported");
}

/// `a_cross_isa_form_is_rejected_before_read` — the family check runs on the
/// declared ID, so a missing asset file is never opened.
#[test]
fn a_cross_isa_form_is_rejected_before_read() {
    let tree = TempTree::new("cross-isa-before-read");
    let mut fixture = mov_r64_fixture();
    fixture.isa_family = "aarch64".to_string();
    fixture.target_dir = "aarch64".to_string();

    // Only the manifest is written: the declared asset path does not exist, so an
    // implementation that opened first would report a host I/O error instead.
    let relative = package_relative(&fixture);
    tree.write(
        &format!("{relative}/package.json"),
        &canonical_bytes(&fixture.json()),
    );

    let error = LoadedPackage::load(tree.root(), &relative)
        .expect_err("the family is decided from the declaration");
    assert_eq!(error.code(), "form-family-mismatch");
    assert_ne!(error.exit_code(), 2, "this is not a host failure");
}
