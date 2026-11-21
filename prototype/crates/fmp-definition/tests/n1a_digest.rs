//! Rows pinned by the cross-language vectors of `ADR-0128` §7.0 and §8.2.
//!
//! Both this file and `tools/check_package_vectors.py` read
//! `fixtures/h2a/digest-vectors.json`; neither one defines its own numbers. The
//! canonical strings in that file are the ADR's strings, and the gate refuses a
//! fixture whose expected digest no longer appears in the ADR.

mod support;

use fmp_definition::digest::{self, Asset, AssetKind};
use fmp_definition::{BuildError, Manifest};
use fmp_model::canonical::{canonical_bytes, sha256};
use fmp_model::json::{self, Json};
use support::{json_of, repository_root, row_for, ManifestFixture};

fn vectors() -> Json {
    let path = repository_root().join("fixtures/h2a/digest-vectors.json");
    let bytes =
        std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    json::parse(&bytes).expect("the vector fixture is JSON")
}

fn string(item: &Json, key: &str) -> String {
    item.get(key)
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("the vector has `{key}`"))
        .to_string()
}

fn array<'a>(root: &'a Json, key: &str) -> &'a [Json] {
    root.get(key)
        .and_then(Json::as_array)
        .unwrap_or_else(|| panic!("the vector file has `{key}`"))
}

fn named<'a>(root: &'a Json, section: &str, name: &str) -> &'a Json {
    array(root, section)
        .iter()
        .find(|item| string(item, "name") == name)
        .unwrap_or_else(|| panic!("no {section} vector named {name}"))
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

/// The preimage is canonical text, not merely JSON: if it were not, two
/// implementations could agree on a digest they both computed over bytes no
/// builder would ever write.
fn assert_canonical(text: &str) {
    let bytes = canonical_bytes(&json_of(text));
    assert_eq!(
        String::from_utf8(bytes).expect("canonical JSON is UTF-8"),
        text,
        "the vector preimage must already be canonical"
    );
}

fn domain_digest_of(vector: &Json) -> String {
    let canonical = string(vector, "canonical");
    assert_canonical(&canonical);
    digest::domain_digest(
        string(vector, "domain").as_bytes(),
        &canonical_bytes(&json_of(&canonical)),
    )
}

fn assets_from(vector: &Json) -> Vec<Asset> {
    array(vector, "assets")
        .iter()
        .map(|asset| {
            let kind = match string(asset, "kind").as_str() {
                "form" => AssetKind::Form,
                "type" => AssetKind::Type,
                "profile" => AssetKind::Profile,
                other => panic!("unknown asset kind {other}"),
            };
            let canonical = string(asset, "canonical");
            assert_canonical(&canonical);
            Asset {
                kind,
                path: string(asset, "path"),
                digest: digest::asset_digest(&json_of(&canonical)),
            }
        })
        .collect()
}

fn hex_bytes(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("hex"))
        .collect()
}

fn mutate_dependency(text: &str, change: &dyn Fn(&mut Json)) -> Result<Manifest, BuildError> {
    let mut value = json_of(text);
    let dependencies = field_mut(&mut value, "dependencies");
    let Json::Array(items) = dependencies else {
        panic!("the fixture has a dependencies array")
    };
    change(&mut items[0]);
    Manifest::from_json(value)
}

/// `the_digest_preimage_vector_matches` — the ADR's fixed bytes reproduce, and
/// the counterexample holds: feeding the nested digest as 32 raw bytes instead of
/// the literal `sha256:<hex>` text produces a different outer digest.
#[test]
fn the_digest_preimage_vector_matches() {
    let root = vectors();

    for vector in array(&root, "domain_vectors") {
        let name = string(vector, "name");
        let expected = string(vector, "expected");
        assert_eq!(domain_digest_of(vector), expected, "{name}");
    }

    for vector in array(&root, "canonical_vectors") {
        let name = string(vector, "name");
        let canonical = string(vector, "canonical");
        assert_canonical(&canonical);
        assert_eq!(
            digest::asset_digest(&json_of(&canonical)),
            string(vector, "expected"),
            "{name}"
        );
    }

    for vector in array(&root, "raw_vectors") {
        let name = string(vector, "name");
        assert_eq!(
            sha256(&[string(vector, "bytes").as_bytes()]),
            string(vector, "expected"),
            "{name}"
        );
    }

    // The preimage rule that is easiest to get wrong: the nested digest is text.
    let source = named(&root, "domain_vectors", "source_package_digest");
    let canonical = string(source, "canonical");
    let expected = string(source, "expected");
    assert_eq!(
        digest::domain_digest(
            b"monasm-package/0.1",
            &canonical_bytes(&json_of(&canonical))
        ),
        expected
    );

    let asset_hex = canonical
        .split("sha256:")
        .nth(1)
        .expect("the record carries the digest as literal text")
        .chars()
        .take(64)
        .collect::<String>();
    let raw = hex_bytes(&asset_hex);
    assert_eq!(raw.len(), 32);
    let marker = format!("\"sha256:{asset_hex}\"");
    let (before, after) = canonical.split_once(&marker).expect("the marker appears");
    let mut wrong = Vec::new();
    wrong.extend_from_slice(b"monasm-package/0.1");
    wrong.push(0);
    wrong.extend_from_slice(before.as_bytes());
    wrong.extend_from_slice(b"\"");
    wrong.extend_from_slice(&raw);
    wrong.extend_from_slice(b"\"");
    wrong.extend_from_slice(after.as_bytes());
    assert_ne!(
        sha256(&[&wrong]),
        expected,
        "raw digest bytes must not reproduce the vector"
    );
}

/// `a_dependency_object_is_closed_and_keeps_its_vector` — the dependent package's
/// bytes reproduce `637edab0…`, the dependency keeps `231b9034…` as literal text,
/// and renaming, dropping, adding or version-floating the object is refused.
#[test]
fn a_dependency_object_is_closed_and_keeps_its_vector() {
    let root = vectors();
    let record = named(&root, "records", "dependent_source");
    let manifest_text = string(record, "manifest");
    let assets = assets_from(record);
    let digest_value = digest::source_package_digest(&json_of(&manifest_text), &assets);
    assert_eq!(digest_value, string(record, "expected_digest"));
    assert!(
        digest_value.starts_with("sha256:637edab0"),
        "{digest_value}"
    );

    let manifest =
        Manifest::parse(manifest_text.as_bytes()).expect("the dependent manifest is legal");
    assert_eq!(manifest.dependencies().len(), 1);
    let dependency = &manifest.dependencies()[0];
    assert_eq!(dependency.package_id, "monasm.x86.base");
    assert_eq!(dependency.version, "0.1.0");
    assert_eq!(
        dependency.source_package_digest,
        "sha256:231b9034ecbe6c9f806f7f2a647295e47a57cddcff47e4afacb24c98510648bf"
    );

    let error = mutate_dependency(&manifest_text, &|entry| match entry {
        Json::Object(fields) => fields.push(("note".to_string(), Json::Str("x".to_string()))),
        _ => panic!("a dependency is an object"),
    })
    .expect_err("an extra key");
    assert_eq!(error.code(), "document-shape");

    let error = mutate_dependency(&manifest_text, &|entry| match entry {
        Json::Object(fields) => {
            fields.retain(|(key, _)| key != "version");
        }
        _ => panic!("a dependency is an object"),
    })
    .expect_err("a missing key");
    assert_eq!(error.code(), "document-shape");

    let error = mutate_dependency(&manifest_text, &|entry| match entry {
        Json::Object(fields) => {
            for (key, slot) in fields.iter_mut() {
                if key == "version" {
                    *slot = Json::Str("latest".to_string());
                }
            }
        }
        _ => panic!("a dependency is an object"),
    })
    .expect_err("a floating version");
    assert_eq!(error.code(), "identifier-lexical");
}

/// `the_bundle_and_release_vectors_match` — `a9bc3395…` and `2416911a…` come out
/// of the two separators; swapping a separator or dropping a key breaks them.
#[test]
fn the_bundle_and_release_vectors_match() {
    let root = vectors();
    let bundle = named(&root, "domain_vectors", "bundle_digest");
    let release = named(&root, "domain_vectors", "release_digest");

    assert_eq!(string(bundle, "domain"), "monasm-bundle/0.1");
    assert_eq!(string(release, "domain"), "monasm-release/0.1");
    for vector in [bundle, release] {
        let actual = domain_digest_of(vector);
        assert_eq!(actual, string(vector, "expected"));
        // The domain is part of the preimage: the same body under the other
        // separator is a different identity, which is why one file cannot be
        // both a bundle and a release.
        let other: &[u8] = if string(vector, "domain") == "monasm-bundle/0.1" {
            b"monasm-release/0.1"
        } else {
            b"monasm-bundle/0.1"
        };
        let canonical = canonical_bytes(&json_of(&string(vector, "canonical")));
        assert_ne!(digest::domain_digest(other, &canonical), actual);
    }
    assert!(string(bundle, "expected").starts_with("sha256:a9bc3395"));
    assert!(string(release, "expected").starts_with("sha256:2416911a"));

    // The public helpers agree with the two named domains.
    let bundle_value = json_of(&string(bundle, "canonical"));
    assert_eq!(
        digest::bundle_digest(&bundle_value),
        string(bundle, "expected")
    );
    let release_value = json_of(&string(release, "canonical"));
    assert_eq!(
        digest::release_digest(&release_value),
        string(release, "expected")
    );
}

/// `the_release_shaped_vector_matches` — `e9473871…` and `45a4004e…`. A release
/// entry carries `evidence_digest`; omitting it produces the development shape,
/// which is a different byte string, so a committed lock cannot be written in it.
#[test]
fn the_release_shaped_vector_matches() {
    let root = vectors();
    let evidence = named(&root, "domain_vectors", "evidence_digest");
    let release = named(&root, "domain_vectors", "release_digest_with_evidence");
    let bare = named(&root, "domain_vectors", "release_digest");

    let evidence_value = json_of(&string(evidence, "canonical"));
    assert_eq!(
        digest::evidence_digest(&evidence_value),
        string(evidence, "expected")
    );
    assert!(string(evidence, "expected").starts_with("sha256:e9473871"));

    let mut release_value = json_of(&string(release, "canonical"));
    assert_eq!(
        digest::release_digest(&release_value),
        string(release, "expected")
    );
    assert!(string(release, "expected").starts_with("sha256:45a4004e"));

    // The development shape is the same metadata without the evidence field, and
    // it is a different identity — the counterexample the ADR names.
    let packages = field_mut(&mut release_value, "packages");
    let Json::Array(items) = packages else {
        panic!("packages is an array")
    };
    match &mut items[0] {
        Json::Object(fields) => fields.retain(|(key, _)| key != "evidence_digest"),
        _ => panic!("a package is an object"),
    }
    assert_eq!(
        digest::release_digest(&release_value),
        string(bare, "expected")
    );
    assert_ne!(string(bare, "expected"), string(release, "expected"));
}

/// `changing_the_legacy_source_changes_the_source_digest` — the legacy source is
/// part of the manifest, so it enters the record. Nothing else in the manifest
/// changes, which is exactly what makes the two snapshots distinguishable.
#[test]
fn changing_the_legacy_source_changes_the_source_digest() {
    let mut old = ManifestFixture::default();
    old.legacy = Some(("x86_64".to_string(), "0.1.0".to_string()));
    let mut new = ManifestFixture::default();
    new.legacy = Some(("x86_64".to_string(), "0.78.0".to_string()));

    let assets = |fixture: &ManifestFixture| -> Vec<Asset> {
        fixture
            .forms
            .iter()
            .map(|(id, path)| {
                let row = json_of(row_for(id));
                Asset {
                    kind: AssetKind::Form,
                    path: path.clone(),
                    digest: digest::asset_digest(&row),
                }
            })
            .collect()
    };

    let old_digest = digest::source_package_digest(&old.json(), &assets(&old));
    let new_digest = digest::source_package_digest(&new.json(), &assets(&new));
    assert_ne!(old_digest, new_digest);

    // The two manifests differ in exactly that one string.
    let old_text = String::from_utf8(canonical_bytes(&old.json())).expect("UTF-8");
    let new_text = String::from_utf8(canonical_bytes(&new.json())).expect("UTF-8");
    assert_eq!(new_text.replace("\"0.78.0\"", "\"0.1.0\""), old_text);
}
