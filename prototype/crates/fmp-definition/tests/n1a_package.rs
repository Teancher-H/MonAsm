//! Rows about one package directory: what is opened, what is consumed, and which
//! facts about it are established before the rows are ever read as a definition.
//!
//! The reader here is the trusted-tree reader: it follows a link if one is on the
//! path, because portable `std::fs` has no no-follow open. Every test in this file
//! is therefore about the *content* of a package, not about the absence of a link
//! on the path used to reach it (`ADR-0128` §3, §9).

mod support;

use fmp_definition::budget::{self, Counter};
use fmp_definition::digest;
use fmp_definition::package::LoadedPackage;
use fmp_model::json::Json;
use support::{
    copy_definition, evidence_manifest, raw_sha256, write_package, write_package_value,
    ManifestFixture, TempTree, MOV_R64_RM, MOV_RM_R64,
};

fn load(tree: &TempTree, relative: &str) -> LoadedPackage {
    LoadedPackage::load(tree.root(), relative)
        .unwrap_or_else(|error| panic!("load {relative}: {error}"))
}

fn field_mut<'a>(value: &'a mut Json, name: &str) -> &'a mut Json {
    match value {
        Json::Object(fields) => match fields.iter_mut().find(|(key, _)| key == name) {
            Some((_, slot)) => slot,
            None => panic!("no field {name}"),
        },
        _ => panic!("not an object"),
    }
}

/// `a_file_change_between_digest_and_merge_is_not_observed` — the digest names
/// the bytes that were parsed, not the path they came from. A change after the
/// open is a different snapshot, never an implicit repair of this one.
#[test]
fn a_file_change_between_digest_and_merge_is_not_observed() {
    let tree = TempTree::new("file-change");
    let fixture = ManifestFixture::default();
    let relative = write_package(&tree, &fixture);

    let first = load(&tree, &relative);
    let asset_digest = first.forms()[0].digest().to_string();
    let source_digest = first.source_package_digest().to_string();
    assert_eq!(
        digest::asset_digest(first.forms()[0].value()),
        asset_digest,
        "the digest is computed from the value that was kept"
    );

    // The reported source digest is recomputable from the values the package
    // exposes. If the digest came from a second read of the same paths, this is
    // the assertion that notices.
    let assets: Vec<digest::Asset> = first
        .forms()
        .iter()
        .map(|form| digest::Asset {
            kind: digest::AssetKind::Form,
            path: form.declared().path.clone(),
            digest: digest::asset_digest(form.value()),
        })
        .collect();
    assert_eq!(
        digest::source_package_digest(first.manifest().canonical(), &assets),
        source_digest
    );

    // Replace the file behind the first row. The loaded package cannot see it.
    tree.write(
        &format!("{relative}/forms/mov-r64-rm.json"),
        MOV_R64_RM.replace("488bc0", "488bc1").as_bytes(),
    );
    assert_eq!(first.forms()[0].digest(), asset_digest);
    assert_eq!(first.source_package_digest(), source_digest);
    assert_eq!(digest::asset_digest(first.forms()[0].value()), asset_digest);

    // A fresh load reads the new bytes: same path, different snapshot.
    let second = load(&tree, &relative);
    assert_ne!(second.source_package_digest(), source_digest);

    // The same bytes in another root replay to the same digest, so nothing in
    // the digest depends on the directory the package happens to live in.
    let replay_root = TempTree::new("file-change-replay");
    let replay = write_package(&replay_root, &fixture);
    let third = load(&replay_root, &replay);
    assert_eq!(third.source_package_digest(), source_digest);
    assert_eq!(third.forms()[0].digest(), asset_digest);
}

/// `a_capability_must_be_declared_if_a_row_uses_it` — the derivation runs on the
/// declared row objects before anything is merged, so a package that declares
/// nothing while its rows place a value or encode an integer is refused with
/// `capability-mismatch`, not accepted with an under-stated requirement.
#[test]
fn a_capability_must_be_declared_if_a_row_uses_it() {
    let tree = TempTree::new("capability-declared");
    let mut fixture =
        ManifestFixture::with_forms(&[("x86:add/rm64-imm8/legacy", "forms/add.json")]);
    fixture.capabilities = Vec::new();
    let relative = write_package(&tree, &fixture);

    let error = LoadedPackage::load(tree.root(), &relative).expect_err("nothing is declared");
    assert_eq!(error.code(), "capability-mismatch");
    let text = error.to_string();
    assert!(text.contains("field-placement/v1"), "{text}");
    assert!(text.contains("integer-domain/v1"), "{text}");
    assert_eq!(error.exit_code(), 1);

    // Declaring both is accepted, and the digest is then computed.
    fixture.capabilities = vec![
        "field-placement/v1".to_string(),
        "integer-domain/v1".to_string(),
    ];
    let relative = write_package(&tree, &fixture);
    let package = load(&tree, &relative);
    assert_eq!(
        package.manifest().requires_capabilities().to_vec(),
        vec![
            "field-placement/v1".to_string(),
            "integer-domain/v1".to_string()
        ]
    );
}

/// `a_case_evidence_must_be_listed_and_hashed` — a present evidence manifest is
/// authoritative in development mode too: a case's `evidence` must resolve to a
/// listed file with the same hash, or the package is `case-evidence-mismatch`.
#[test]
fn a_case_evidence_must_be_listed_and_hashed() {
    let tree = TempTree::new("case-evidence");
    let fixture = ManifestFixture::default();
    let relative = write_package(&tree, &fixture);

    let case_bytes = b"{\"case_id\":\"c1\"}\n";
    let case_hash = raw_sha256(case_bytes);
    let cases = format!(
        "{{\"cases\":[{{\"case_id\":\"c1\",\"evidence\":{{\"path\":\"evidence/case-1.json\",\"sha256\":\"{case_hash}\"}}}}],\"cases_format\":\"monasm-cases/0.1\"}}"
    );
    let notice = b"MonAsm. SPDX-License-Identifier: Apache-2.0\n";
    tree.write(&format!("{relative}/NOTICE"), notice);
    tree.write(&format!("{relative}/tests/cases.json"), cases.as_bytes());
    tree.write(&format!("{relative}/evidence/case-1.json"), case_bytes);

    // The case references evidence/case-1.json, which the manifest does not list.
    let unlisted = evidence_manifest(
        &[
            ("NOTICE".to_string(), raw_sha256(notice)),
            ("tests/cases.json".to_string(), raw_sha256(cases.as_bytes())),
        ],
        "manual-derivation",
    );
    tree.write(
        &format!("{relative}/evidence/manifest.json"),
        unlisted.as_bytes(),
    );
    let error =
        LoadedPackage::load(tree.root(), &relative).expect_err("the case evidence is unlisted");
    assert_eq!(error.code(), "case-evidence-mismatch");
    assert!(
        error.to_string().contains("evidence/case-1.json"),
        "{error}"
    );

    // Listed, but the case's own hash disagrees with the listed one.
    let listed = evidence_manifest(
        &[
            ("NOTICE".to_string(), raw_sha256(notice)),
            ("evidence/case-1.json".to_string(), case_hash.clone()),
            ("tests/cases.json".to_string(), raw_sha256(cases.as_bytes())),
        ],
        "manual-derivation",
    );
    let wrong = format!(
        "{{\"cases\":[{{\"case_id\":\"c1\",\"evidence\":{{\"path\":\"evidence/case-1.json\",\"sha256\":\"{}\"}}}}],\"cases_format\":\"monasm-cases/0.1\"}}",
        "0".repeat(64)
    );
    tree.write(&format!("{relative}/tests/cases.json"), wrong.as_bytes());
    let listed = listed.replace(&raw_sha256(cases.as_bytes()), &raw_sha256(wrong.as_bytes()));
    tree.write(
        &format!("{relative}/evidence/manifest.json"),
        listed.as_bytes(),
    );
    let error = LoadedPackage::load(tree.root(), &relative).expect_err("the case hash differs");
    assert_eq!(error.code(), "case-evidence-mismatch");

    // The honest form loads and reports an evidence digest.
    let agreed = format!(
        "{{\"cases\":[{{\"case_id\":\"c1\",\"evidence\":{{\"path\":\"evidence/case-1.json\",\"sha256\":\"{case_hash}\"}}}}],\"cases_format\":\"monasm-cases/0.1\"}}"
    );
    tree.write(&format!("{relative}/tests/cases.json"), agreed.as_bytes());
    let agreed_manifest = evidence_manifest(
        &[
            ("NOTICE".to_string(), raw_sha256(notice)),
            ("evidence/case-1.json".to_string(), case_hash),
            (
                "tests/cases.json".to_string(),
                raw_sha256(agreed.as_bytes()),
            ),
        ],
        "manual-derivation",
    );
    tree.write(
        &format!("{relative}/evidence/manifest.json"),
        agreed_manifest.as_bytes(),
    );
    let package = load(&tree, &relative);
    assert!(package.evidence_digest().is_some());
    package
        .check_release_evidence()
        .expect("a complete release evidence set");
}

/// `an_evidence_hash_covers_raw_file_bytes` — the recorded `sha256` is over the
/// committed bytes, so a line-ending edit is a real change and is caught.
#[test]
fn an_evidence_hash_covers_raw_file_bytes() {
    let tree = TempTree::new("raw-bytes");
    let fixture = ManifestFixture::default();
    let relative = write_package(&tree, &fixture);

    let lf = b"a\nb\n";
    let crlf = b"a\r\nb\r\n";
    assert_ne!(raw_sha256(lf), raw_sha256(crlf));

    let cases = b"{\"cases\":[],\"cases_format\":\"monasm-cases/0.1\"}\n";
    tree.write(&format!("{relative}/tests/cases.json"), cases);
    tree.write(&format!("{relative}/NOTICE"), lf);
    let manifest = evidence_manifest(
        &[
            ("NOTICE".to_string(), raw_sha256(lf)),
            ("tests/cases.json".to_string(), raw_sha256(cases)),
        ],
        "manual-derivation",
    );
    tree.write(
        &format!("{relative}/evidence/manifest.json"),
        manifest.as_bytes(),
    );
    load(&tree, &relative);

    // One line-ending change moves the raw bytes and nothing else.
    tree.write(&format!("{relative}/NOTICE"), crlf);
    let error = LoadedPackage::load(tree.root(), &relative).expect_err("CRLF is a change");
    assert_eq!(error.code(), "evidence-mismatch");
    assert!(error.to_string().contains("NOTICE"), "{error}");
}

/// `the_release_mode_requires_complete_evidence` — development mode may omit the
/// manifest; release mode may not, and every missing item has its own name.
#[test]
fn the_release_mode_requires_complete_evidence() {
    let tree = TempTree::new("release-evidence");
    let fixture = ManifestFixture::default();
    let relative = write_package(&tree, &fixture);

    // No manifest at all: the package loads in development mode.
    let package = load(&tree, &relative);
    assert!(package.evidence().is_none());
    let error = package
        .check_release_evidence()
        .expect_err("a release needs evidence");
    assert_eq!(error.code(), "evidence-incomplete");
    assert!(error.to_string().contains("manifest.json"), "{error}");

    let cases = b"{\"cases\":[],\"cases_format\":\"monasm-cases/0.1\"}\n";
    tree.write(&format!("{relative}/tests/cases.json"), cases);
    let notice = b"MonAsm. SPDX-License-Identifier: Apache-2.0\n";
    tree.write(&format!("{relative}/NOTICE"), notice);

    // Missing NOTICE in `files`.
    let without_notice = evidence_manifest(
        &[("tests/cases.json".to_string(), raw_sha256(cases))],
        "manual-derivation",
    )
    .replace(
        "{\"note\":\"pinned rows\",\"path\":\"NOTICE\"}",
        "{\"note\":\"pinned rows\",\"path\":\"tests/cases.json\"}",
    );
    tree.write(
        &format!("{relative}/evidence/manifest.json"),
        without_notice.as_bytes(),
    );
    let error = load(&tree, &relative)
        .check_release_evidence()
        .expect_err("NOTICE is required");
    assert_eq!(error.code(), "evidence-incomplete");
    assert!(error.to_string().contains("NOTICE"), "{error}");

    // Complete files, but no sources entry.
    let no_sources = evidence_manifest(
        &[
            ("NOTICE".to_string(), raw_sha256(notice)),
            ("tests/cases.json".to_string(), raw_sha256(cases)),
        ],
        "manual-derivation",
    )
    .replace("[{\"note\":\"pinned rows\",\"path\":\"NOTICE\"}]", "[]");
    tree.write(
        &format!("{relative}/evidence/manifest.json"),
        no_sources.as_bytes(),
    );
    let error = load(&tree, &relative)
        .check_release_evidence()
        .expect_err("a source is required");
    assert_eq!(error.code(), "evidence-incomplete");
    assert!(error.to_string().contains("sources"), "{error}");

    // `not-applicable` is reserved for a formless package, which 0.1 refuses.
    let not_applicable = evidence_manifest(
        &[
            ("NOTICE".to_string(), raw_sha256(notice)),
            ("tests/cases.json".to_string(), raw_sha256(cases)),
        ],
        "not-applicable",
    );
    tree.write(
        &format!("{relative}/evidence/manifest.json"),
        not_applicable.as_bytes(),
    );
    let error = load(&tree, &relative)
        .check_release_evidence()
        .expect_err("not-applicable is not a release value here");
    assert_eq!(error.code(), "evidence-incomplete");
}

/// `the_asset_budget_is_counted_while_reading` — the per-file limit is checked
/// against what is actually read, and the cumulative counter is charged per read.
/// A metadata hint alone would let a growing file or a stack of files through.
#[test]
fn the_asset_budget_is_counted_while_reading() {
    let tree = TempTree::new("asset-budget");
    let small = tree.write("forms/a.json", b"{\"a\":1}\n");

    let error = budget::read_regular(&small, 4, "form asset bytes", &mut Counter::package())
        .expect_err("9 bytes exceed a 4-byte limit");
    assert_eq!(error.code(), "resource-limit");

    // Two 6-byte files against a 10-byte counter: the first is charged, the
    // second cannot fit even though its own per-file limit would allow it.
    let first = tree.write("forms/first.json", b"123456");
    let second = tree.write("forms/second.json", b"123456");
    let mut counter = Counter::new("test budget", 10);
    let bytes = budget::read_regular(&first, 100, "test budget", &mut counter).expect("6 of 10");
    assert_eq!(bytes.len(), 6);
    assert_eq!(counter.spent(), 6);
    let error = budget::read_regular(&second, 100, "test budget", &mut counter)
        .expect_err("only 4 bytes remain");
    assert_eq!(error.code(), "resource-limit");
    assert_eq!(counter.spent(), 6, "a refused read is not charged");
}

/// `only_executable_inputs_enter_the_source_digest` — the record names the
/// declared form assets and nothing else. Documentation, the evidence manifest
/// and the case file are outside the source digest by construction, because the
/// builder never opens them for it.
#[test]
fn only_executable_inputs_enter_the_source_digest() {
    let tree = TempTree::new("source-digest");
    let fixture = ManifestFixture::default();
    let relative = write_package(&tree, &fixture);

    let before = load(&tree, &relative).source_package_digest().to_string();

    // Files that are not declared assets do not enter the record.
    tree.write(&format!("{relative}/README.md"), b"# a package\n");
    tree.write(&format!("{relative}/NOTICE"), b"Apache-2.0\n");
    tree.write(&format!("{relative}/evidence/notes.md"), b"notes\n");
    let after = load(&tree, &relative).source_package_digest().to_string();
    assert_eq!(before, after);

    // Even a complete evidence manifest leaves the source digest alone.
    let cases = b"{\"cases\":[],\"cases_format\":\"monasm-cases/0.1\"}\n";
    tree.write(&format!("{relative}/tests/cases.json"), cases);
    let manifest = evidence_manifest(
        &[
            ("NOTICE".to_string(), raw_sha256(b"Apache-2.0\n")),
            ("tests/cases.json".to_string(), raw_sha256(cases)),
        ],
        "manual-derivation",
    );
    tree.write(
        &format!("{relative}/evidence/manifest.json"),
        manifest.as_bytes(),
    );
    let with_evidence = load(&tree, &relative);
    assert!(with_evidence.evidence_digest().is_some());
    assert_eq!(with_evidence.source_package_digest(), before);

    // A form row is an executable input: changing one moves the digest.
    tree.write(
        &format!("{relative}/forms/mov-r64-rm.json"),
        MOV_R64_RM.replace("488bc0", "488bc1").as_bytes(),
    );
    let changed = load(&tree, &relative).source_package_digest().to_string();
    assert_ne!(changed, before);
}

/// `an_evidence_entry_must_stay_inside_the_package_and_match_its_hash` — an
/// escaping path is refused before the open, an absent file is not "optional",
/// and a wrong hash is a rejection rather than a warning.
#[test]
fn an_evidence_entry_must_stay_inside_the_package_and_match_its_hash() {
    let tree = TempTree::new("evidence-entry");
    let fixture = ManifestFixture::default();
    let relative = write_package(&tree, &fixture);
    let notice = b"MonAsm.\n";
    tree.write(&format!("{relative}/NOTICE"), notice);

    let escaping = "{\"evidence_format\":\"monasm-evidence/0.1\",\"files\":[{\"path\":\"../outside.md\",\"sha256\":\""
        .to_string()
        + &"0".repeat(64)
        + "\"}],\"oracle\":{\"command\":\"manual\",\"skips\":[],\"status\":\"manual-derivation\"},\"sources\":[{\"note\":\"x\",\"path\":\"../outside.md\"}]}";
    tree.write(
        &format!("{relative}/evidence/manifest.json"),
        escaping.as_bytes(),
    );
    let error = LoadedPackage::load(tree.root(), &relative).expect_err("an escaping path");
    assert_eq!(error.code(), "evidence-mismatch");
    assert_eq!(error.exit_code(), 1);

    let absent = evidence_manifest(
        &[
            ("NOTICE".to_string(), raw_sha256(notice)),
            ("evidence/missing.md".to_string(), raw_sha256(b"x")),
        ],
        "manual-derivation",
    );
    tree.write(
        &format!("{relative}/evidence/manifest.json"),
        absent.as_bytes(),
    );
    let error = LoadedPackage::load(tree.root(), &relative).expect_err("an absent file");
    assert_eq!(error.code(), "evidence-mismatch");

    tree.write(&format!("{relative}/evidence/missing.md"), b"y\n");
    let error = LoadedPackage::load(tree.root(), &relative).expect_err("a wrong hash");
    assert_eq!(error.code(), "evidence-mismatch");
    assert!(error.to_string().contains("hash"), "{error}");
}

/// `a_legacy_package_target_must_match_its_source` — row equality alone is not
/// enough: a package whose rows are the pinned rows but whose target claims a
/// different execution mode or address width is a different machine.
#[test]
fn a_legacy_package_target_must_match_its_source() {
    let tree = TempTree::new("legacy-target");
    copy_definition(&tree, "x86_64", "0.1.0");
    let fixture = ManifestFixture::default();
    let relative = write_package(&tree, &fixture);
    load(&tree, &relative)
        .check_legacy(tree.root())
        .expect("the fixture matches its source");

    for (field, replacement) in [("execution_mode", "32"), ("isa_variant", "x86-32")] {
        let mut value = fixture.json();
        let identity = field_mut(&mut value, "target_identity");
        *field_mut(identity, field) = Json::Str(replacement.to_string());
        let relative = write_package_value(&tree, &fixture, &value);
        let package = load(&tree, &relative);
        let error = package
            .check_legacy(tree.root())
            .expect_err("the target disagrees with the pinned definition");
        assert_eq!(error.code(), "legacy-target-mismatch", "{field}");
        assert_eq!(error.exit_code(), 1);
    }

    // The address width is a number, so it is compared as one.
    let mut value = fixture.json();
    let identity = field_mut(&mut value, "target_identity");
    *field_mut(identity, "address_width") = Json::Int(32);
    let relative = write_package_value(&tree, &fixture, &value);
    let error = load(&tree, &relative)
        .check_legacy(tree.root())
        .expect_err("address_width 32");
    assert_eq!(error.code(), "legacy-target-mismatch");
    assert!(error.to_string().contains("address_width"), "{error}");
}

/// `a_set_equal_target_migrates_a_differently_ordered_legacy_array` — the frozen
/// corpus keeps its published spelling, so extensions are compared as sets. The
/// package itself still writes the one strictly increasing spelling.
#[test]
fn a_set_equal_target_migrates_a_differently_ordered_legacy_array() {
    let tree = TempTree::new("set-equal-target");
    // A pinned definition whose extension list is in a different order than the
    // ordering rule the package obeys. Only the two rows and the identity matter
    // to `check_legacy`, which is why this synthetic file is enough here; a real
    // definition's `read` is a later node's check.
    let legacy = format!(
        "{{\"definition_format\":\"fmp-def/0.1\",\"forms\":[{},{}],\"namespace\":\"monasm.isa.x86\",\"target_identity\":{{\"address_width\":64,\"byte_order\":\"little\",\"enabled_extensions\":[\"avx512vl\",\"avx\",\"avx512f\"],\"execution_mode\":\"64\",\"isa_family\":\"x86\",\"isa_variant\":\"x86-64\"}},\"version\":\"9.9.9\"}}",
        MOV_R64_RM, MOV_RM_R64
    );
    tree.write("definitions/x86_64/9.9.9.json", legacy.as_bytes());

    let fixture = ManifestFixture {
        legacy: Some(("x86_64".to_string(), "9.9.9".to_string())),
        extensions: vec![
            "avx".to_string(),
            "avx512f".to_string(),
            "avx512vl".to_string(),
        ],
        forms: vec![(
            "x86:mov/r64-rm/legacy".to_string(),
            "forms/mov.json".to_string(),
        )],
        ..ManifestFixture::default()
    };
    let relative = write_package(&tree, &fixture);
    load(&tree, &relative)
        .check_legacy(tree.root())
        .expect("the same set in a different order is the same target");

    // A different set is not: same order rule, one member missing.
    let mut value = fixture.json();
    let identity = field_mut(&mut value, "target_identity");
    *field_mut(identity, "enabled_extensions") = Json::Array(vec![
        Json::Str("avx".to_string()),
        Json::Str("avx512f".to_string()),
    ]);
    let relative = write_package_value(&tree, &fixture, &value);
    let error = load(&tree, &relative)
        .check_legacy(tree.root())
        .expect_err("a strict subset is not the same set");
    assert_eq!(error.code(), "legacy-target-mismatch");
    assert!(error.to_string().contains("enabled_extensions"), "{error}");
}

/// `every_package_form_equals_the_pinned_legacy_row` — each exported row is
/// compared canonically with the row of the pinned file. A reordered but equal
/// row is equal; a changed template is not.
#[test]
fn every_package_form_equals_the_pinned_legacy_row() {
    let tree = TempTree::new("legacy-rows");
    copy_definition(&tree, "x86_64", "0.1.0");
    let fixture = ManifestFixture::default();
    let relative = write_package(&tree, &fixture);

    let package = load(&tree, &relative);
    package
        .check_legacy(tree.root())
        .expect("both rows equal the pinned rows");
    assert_eq!(package.forms().len(), 2);

    // A canonical re-spelling of the same row is still the same row.
    let reordered = MOV_RM_R64
        .replacen("{\"form_id\":", "{\"template\":\"4889c0\",\"form_id\":", 1)
        .replace(",\"template\":\"4889c0\"}", "}");
    tree.write(
        &format!("{relative}/forms/mov-rm-r64.json"),
        reordered.as_bytes(),
    );
    let package = load(&tree, &relative);
    package
        .check_legacy(tree.root())
        .expect("key order does not change a canonical row");

    // A changed template is a different row.
    tree.write(
        &format!("{relative}/forms/mov-rm-r64.json"),
        MOV_RM_R64.replace("4889c0", "4889c1").as_bytes(),
    );
    let package = load(&tree, &relative);
    let error = package
        .check_legacy(tree.root())
        .expect_err("the template differs");
    assert_eq!(error.code(), "legacy-row-mismatch");
    assert!(
        error.to_string().contains("x86:mov/rm-r64/legacy"),
        "{error}"
    );
}

/// `a_form_row_is_compared_against_its_pinned_version_not_the_newest_file` — the
/// declared legacy version decides which file is read. A row that only exists in
/// the newest table is not found in `0.1.0`, even though the newest file is right
/// there and would contain it.
#[test]
fn a_form_row_is_compared_against_its_pinned_version_not_the_newest_file() {
    let tree = TempTree::new("pinned-version");
    copy_definition(&tree, "x86_64", "0.1.0");
    copy_definition(&tree, "x86_64", "0.78.0");

    let mut fixture =
        ManifestFixture::with_forms(&[("x86:mov/r64-riprel32/legacy", "forms/riprel.json")]);
    fixture.definition_format = "fmp-def/0.2".to_string();
    fixture.capabilities = vec![
        "field-placement/v1".to_string(),
        "integer-domain/v1".to_string(),
    ];
    fixture.extensions = vec![
        "avx".to_string(),
        "avx512f".to_string(),
        "avx512vl".to_string(),
    ];
    fixture.legacy = Some(("x86_64".to_string(), "0.78.0".to_string()));
    let relative = write_package(&tree, &fixture);
    load(&tree, &relative)
        .check_legacy(tree.root())
        .expect("the row exists in the pinned 0.78.0 table");

    // Point the same package at 0.1.0 and at that file's (empty) extension set,
    // so the target check passes and the row lookup is what rejects it. The
    // newest file still exists in the tree, so an implementation that silently
    // upgraded would pass; the declared version is what is read.
    let mut value = fixture.json();
    let legacy = field_mut(&mut value, "legacy_source");
    *field_mut(legacy, "version") = Json::Str("0.1.0".to_string());
    let identity = field_mut(&mut value, "target_identity");
    *field_mut(identity, "enabled_extensions") = Json::Array(Vec::new());
    let relative = write_package_value(&tree, &fixture, &value);
    let package = load(&tree, &relative);
    let error = package
        .check_legacy(tree.root())
        .expect_err("0.1.0 has no such row");
    assert_eq!(error.code(), "legacy-row-mismatch");
    assert!(
        error.to_string().contains("x86:mov/r64-riprel32/legacy"),
        "{error}"
    );
}
