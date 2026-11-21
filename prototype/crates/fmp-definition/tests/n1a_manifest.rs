//! Rows decided on a single manifest document: closed shape, the capability
//! equation of `ADR-0128` §1.2, the reserved asset lists of §5 and the explicit
//! bounds of §12.
//!
//! Nothing here opens a file. That is the point: a manifest that is going to be
//! rejected is rejected before the package's rows are read, so the rejection does
//! not depend on what those rows contain or on whether they exist.

mod support;

use fmp_definition::budget::{self, Counter};
use fmp_definition::manifest::{check_capabilities, derive_capabilities};
use fmp_definition::{BuildError, Manifest};
use fmp_model::json::Json;
use support::{json_of, ManifestFixture, ADD_RM64_IMM8, MOV_R64_RM};

fn parse_with(
    fixture: &ManifestFixture,
    mutate: impl FnOnce(&mut Json),
) -> Result<Manifest, BuildError> {
    let mut value = fixture.json();
    mutate(&mut value);
    Manifest::from_json(value)
}

fn field_mut<'a>(value: &'a mut Json, name: &str) -> &'a mut Json {
    match value {
        Json::Object(entries) => match entries.iter_mut().find(|(key, _)| key == name) {
            Some((_, slot)) => slot,
            None => panic!("the fixture has `{name}`"),
        },
        _ => panic!("the fixture root is an object"),
    }
}

fn remove_field(value: &mut Json, name: &str) {
    match value {
        Json::Object(entries) => {
            let before = entries.len();
            entries.retain(|(key, _)| key != name);
            assert_eq!(before, entries.len() + 1, "the fixture has `{name}`");
        }
        _ => panic!("the fixture root is an object"),
    }
}

fn insert_field(value: &mut Json, name: &str, field: Json) {
    match value {
        Json::Object(entries) => entries.push((name.to_string(), field)),
        _ => panic!("the fixture root is an object"),
    }
}

/// `the_manifest_is_closed` — an unknown key, a missing required key, a wrong
/// type and a duplicated key are rejections; an absent optional key is not.
/// An open object would let a newer document be read as an older one.
#[test]
fn the_manifest_is_closed() {
    let fixture = ManifestFixture::default();
    assert!(
        Manifest::from_json(fixture.json()).is_ok(),
        "the fixture is legal"
    );

    let error = parse_with(&fixture, |value| {
        insert_field(value, "author_notes", Json::Str("later".to_string()));
    })
    .expect_err("an unknown key");
    assert_eq!(error.code(), "document-shape");
    assert!(error.to_string().contains("unknown field"), "{error}");

    let error =
        parse_with(&fixture, |value| remove_field(value, "version")).expect_err("no version");
    assert_eq!(error.code(), "document-shape");
    assert!(error.to_string().contains("missing"), "{error}");

    let error = parse_with(&fixture, |value| {
        *field_mut(value, "version") = Json::Int(1);
    })
    .expect_err("a numeric version");
    assert_eq!(error.code(), "document-shape");
    assert!(error.to_string().contains("expected string"), "{error}");

    // A duplicate key is a document the reader must not resolve by last-wins.
    let text = fixture.text();
    let duplicated = format!("{{\"version\":\"0.1.0\",{}", &text[1..]);
    let error = Manifest::parse(duplicated.as_bytes()).expect_err("a duplicate key");
    assert_eq!(error.code(), "document-shape");
    assert!(error.to_string().contains("duplicate key"), "{error}");

    // Absent optional keys: `legacy_source` is for a migrated package and the two
    // reserved asset lists are optional. A new package may omit all three.
    let mut bare = ManifestFixture::default();
    bare.legacy = None;
    bare.include_reserved_assets = false;
    let manifest = Manifest::from_json(bare.json()).expect("the optional keys may be absent");
    assert!(manifest.legacy_source().is_none());
    assert!(manifest.types().is_empty());
    assert!(manifest.profiles().is_empty());
}

/// `an_empty_forms_list_is_refused` — `monasm-package/0.1` has no zero-form
/// package, and the rejection happens before any row would be read.
#[test]
fn an_empty_forms_list_is_refused() {
    let fixture = ManifestFixture::with_forms(&[]);
    let error = Manifest::from_json(fixture.json()).expect_err("no exported forms");
    assert_eq!(error.code(), "empty-package");
    assert_eq!(error.exit_code(), 1);
}

/// `an_unknown_capability_is_refused` — the whitelist is part of the format, so
/// a name outside it is rejected instead of being carried into a digest.
#[test]
fn an_unknown_capability_is_refused() {
    let mut fixture = ManifestFixture::default();
    fixture.capabilities = vec!["field-placement/v1".to_string(), "teleport/v1".to_string()];
    let error = Manifest::from_json(fixture.json()).expect_err("an unknown capability");
    assert_eq!(error.code(), "unsupported-capability");
    assert!(error.to_string().contains("teleport/v1"), "{error}");
}

/// `a_declared_capability_must_be_used_by_a_row` — the comparison is equality in
/// both directions. A declaration that names a primitive no row uses turns the
/// field into a wish list that a reader cannot trust.
#[test]
fn a_declared_capability_must_be_used_by_a_row() {
    let mut fixture = ManifestFixture::with_forms(&[("x86:mov/r64-rm/legacy", "forms/mov.json")]);
    fixture.capabilities = vec![
        "field-placement/v1".to_string(),
        "integer-domain/v1".to_string(),
    ];
    let manifest = Manifest::from_json(fixture.json()).expect("the declaration is well formed");

    let row = json_of(MOV_R64_RM);
    let derived = derive_capabilities(&[&row]);
    assert_eq!(derived, vec!["field-placement/v1".to_string()]);
    let error = check_capabilities(manifest.requires_capabilities(), &derived)
        .expect_err("integer-domain/v1 is declared but unused");
    assert_eq!(error.code(), "capability-mismatch");
    match error {
        BuildError::CapabilityMismatch { declared, derived } => {
            assert_eq!(declared.len(), 2);
            assert_eq!(derived, vec!["field-placement/v1".to_string()]);
        }
        other => panic!("expected capability-mismatch, got {other}"),
    }
    // The row really does derive the placement capability, so an empty
    // declaration would fail in the other direction.
    assert_eq!(
        derive_capabilities(&[&row]),
        vec!["field-placement/v1".to_string()]
    );
    assert!(check_capabilities(&[], &derive_capabilities(&[&row])).is_err());
}

/// `a_duplicated_capability_is_rejected` — a flat set has one legal spelling, so
/// a repeated member is a format rejection and never enters a digest.
#[test]
fn a_duplicated_capability_is_rejected() {
    let mut fixture = ManifestFixture::default();
    fixture.capabilities = vec![
        "field-placement/v1".to_string(),
        "field-placement/v1".to_string(),
    ];
    let error = Manifest::from_json(fixture.json()).expect_err("a duplicated capability");
    assert_eq!(error.code(), "capability-lexical");
}

/// `a_reversed_extension_array_is_rejected` — extensions are strictly increasing
/// under code-point order. Sorting a reversed array would mint a second spelling
/// of one set, and with it a second `source_package_digest` for one package.
#[test]
fn a_reversed_extension_array_is_rejected() {
    let mut fixture = ManifestFixture::default();
    fixture.extensions = vec!["avx512f".to_string(), "avx".to_string()];
    let error = Manifest::from_json(fixture.json()).expect_err("a reversed array");
    assert_eq!(error.code(), "extension-lexical");

    let mut duplicated = ManifestFixture::default();
    duplicated.extensions = vec!["avx".to_string(), "avx".to_string()];
    let error = Manifest::from_json(duplicated.json()).expect_err("a duplicated array");
    assert_eq!(error.code(), "extension-lexical");

    let mut sorted = ManifestFixture::default();
    sorted.extensions = vec!["avx".to_string(), "avx512f".to_string()];
    assert!(Manifest::from_json(sorted.json()).is_ok());
}

/// `a_non_empty_reserved_asset_is_refused` — `exports.types` and
/// `exports.profiles` are declared and digested, but H2 merges no asset whose
/// semantics no reader defines, so a non-empty list is refused rather than
/// half-merged.
#[test]
fn a_non_empty_reserved_asset_is_refused() {
    for kind in ["types", "profiles"] {
        let fixture = ManifestFixture::default();
        let error = parse_with(&fixture, |value| {
            let exports = field_mut(value, "exports");
            *field_mut(exports, kind) =
                json_of(r#"[{"id":"x86:example/type","path":"types/example.json"}]"#);
        })
        .expect_err("a reserved asset");
        assert_eq!(error.code(), "unsupported-asset", "{kind}");
        match &error {
            BuildError::UnsupportedAsset { kind: actual } => {
                assert_eq!(*actual, if kind == "types" { "type" } else { "profile" });
            }
            other => panic!("expected unsupported-asset, got {other}"),
        }
    }

    // Empty lists are accepted and record zero assets.
    let empty = ManifestFixture::default();
    let manifest = Manifest::from_json(empty.json()).expect("empty reserved lists");
    assert!(manifest.types().is_empty());
    assert!(manifest.profiles().is_empty());
}

/// `a_non_empty_reserved_asset_is_refused_forever_under_0_1` — the meaning of a
/// document is a property of its declared `package_format`. A future builder
/// reads `monasm-package/0.2` as a different document (or rejects it), so the
/// same bytes cannot silently change from `unsupported-asset` to accepted.
#[test]
fn a_non_empty_reserved_asset_is_refused_forever_under_0_1() {
    let fixture = ManifestFixture::default();
    let with_type = |value: &mut Json| {
        let exports = field_mut(value, "exports");
        *field_mut(exports, "types") =
            json_of(r#"[{"id":"x86:example/type","path":"types/t.json"}]"#);
    };

    let error = parse_with(&fixture, with_type).expect_err("reserved under 0.1");
    assert_eq!(error.code(), "unsupported-asset");

    let error = parse_with(&fixture, |value| {
        with_type(value);
        *field_mut(value, "package_format") = Json::Str("monasm-package/0.2".to_string());
    })
    .expect_err("0.2 is not this reader's format");
    assert_eq!(error.code(), "document-shape");
    assert!(
        error.to_string().contains("monasm-package/0.2"),
        "the rejection names the unread format: {error}"
    );
}

/// `a_deep_json_document_is_refused_before_recursion` — the depth scan is
/// iterative and runs on the raw bytes, because `fmp_model::json::parse`
/// descends recursively and a small document would otherwise exhaust the stack
/// instead of being rejected.
#[test]
fn a_deep_json_document_is_refused_before_recursion() {
    let mut deep = vec![b'['; 65];
    deep.extend(std::iter::repeat(b']').take(65));
    let error = Manifest::parse(&deep).expect_err("65 levels");
    assert_eq!(error.code(), "resource-limit");
    assert!(error.to_string().contains("depth"), "{error}");

    // 64 is inside the budget; the parser then rejects the value for its shape.
    let mut allowed = vec![b'['; 64];
    allowed.extend(std::iter::repeat(b']').take(64));
    assert!(budget::check_depth(&allowed).is_ok());
    let error = Manifest::parse(&allowed).expect_err("an array is not a manifest");
    assert_eq!(error.code(), "document-shape");
}

/// `resource_limits_are_enforced` — the entry point for §12. The per-layer rows
/// live with their layers; what is asserted here is that each bound exists as a
/// rejection and not as a heap allocation or a stack overflow.
#[test]
fn resource_limits_are_enforced() {
    let long = "a".repeat(budget::PATH_BYTES as usize + 1);
    let error = budget::check_path_length("form asset path", &long).expect_err("1025 bytes");
    assert_eq!(error.code(), "resource-limit");

    let mut counter = Counter::package();
    counter
        .charge(budget::PACKAGE_BYTES)
        .expect("the budget itself");
    assert_eq!(counter.remaining(), 0);
    let error = counter.charge(1).expect_err("one byte past the budget");
    assert_eq!(error.code(), "resource-limit");

    // 2049 declared assets cross `ASSETS_PER_PACKAGE` before the ordering rule is
    // even consulted; a package cannot buy more forms with a longer manifest.
    let mut fixture = ManifestFixture::default();
    fixture.forms = (0..=budget::ASSETS_PER_PACKAGE)
        .map(|index| {
            (
                format!("x86:a{index:04}/legacy"),
                format!("forms/a{index:04}.json"),
            )
        })
        .collect();
    let error = Manifest::from_json(fixture.json()).expect_err("2049 assets");
    assert_eq!(error.code(), "resource-limit");

    // The depth budget is one of the same family and is charged before parsing.
    assert_eq!(budget::JSON_DEPTH, 64);
    assert_eq!(budget::FORMS_PER_PACKAGE, 1024);
    assert_eq!(budget::EVIDENCE_FILES, 4096);
    // `ADD_RM64_IMM8` is the row the capability derivation reads; keeping it
    // referenced here makes the limits table's row count auditable.
    let add = json_of(ADD_RM64_IMM8);
    assert_eq!(derive_capabilities(&[&add]).len(), 2);
}
