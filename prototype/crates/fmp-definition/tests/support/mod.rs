#![allow(dead_code)]

//! Fixtures shared by the N1a tests: canonical manifests, the two real x86 rows
//! of the pinned `0.1.0` table, and a disposable tree.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fmp_model::canonical::canonical_bytes;
use fmp_model::json::{self, Json};

/// `x86:mov/r64-rm/legacy`, byte for byte from `definitions/x86_64/0.1.0.json`.
pub const MOV_R64_RM: &str = r#"{"form_id":"x86:mov/r64-rm/legacy","slots":[{"from":"reg_number","kind":"x86.gpr64","modifiers":[],"placements":[{"bit_offset":19,"width":3}],"role":"dest","target_type":"r64"},{"from":"reg_number","kind":"x86.gpr64","modifiers":[],"placements":[{"bit_offset":16,"width":3}],"role":"src","target_type":"rm64"}],"template":"488bc0"}"#;

/// `x86:mov/rm-r64/legacy`, the second §1 row.
pub const MOV_RM_R64: &str = r#"{"form_id":"x86:mov/rm-r64/legacy","slots":[{"from":"reg_number","kind":"x86.gpr64","modifiers":[],"placements":[{"bit_offset":16,"width":3}],"role":"dest","target_type":"rm64"},{"from":"reg_number","kind":"x86.gpr64","modifiers":[],"placements":[{"bit_offset":19,"width":3}],"role":"src","target_type":"r64"}],"template":"4889c0"}"#;

/// `x86:add/rm64-imm8/legacy`: one register slot and one `operand_value` slot, so
/// it derives both capabilities.
pub const ADD_RM64_IMM8: &str = r#"{"form_id":"x86:add/rm64-imm8/legacy","slots":[{"from":"reg_number","kind":"x86.gpr64","modifiers":[],"placements":[{"bit_offset":16,"width":3}],"role":"dest","target_type":"rm64"},{"from":"operand_value","kind":"x86.imm","modifiers":[],"placements":[{"bit_offset":24,"width":8}],"range":{"align_bits":0,"bits":8,"signed":true},"role":"imm","target_type":"imm8"}],"template":"4883c000"}"#;

/// A row that exists only in the newer `0.78.0` table (`fmp-def/0.2` shape).
pub const MOV_R64_RIPREL32: &str = r#"{"form_id":"x86:mov/r64-riprel32/legacy","requires_extensions":[],"slots":[{"from":"reg_number","kind":"x86.gpr64","modifiers":[],"placements":[{"bit_offset":2,"width":1},{"bit_offset":19,"width":3}],"role":"dest","target_type":"r64"},{"from":"operand_value","kind":"x86.rel","modifiers":[],"placements":[{"bit_offset":24,"width":32}],"range":{"align_bits":0,"bits":32,"signed":true},"role":"target","target_type":"riprel32"}],"template":"488b0500000000"}"#;

/// The `ADR-0128` §7.0 preimage fixture manifest.
pub const EXAMPLE_MANIFEST: &str = r#"{"definition_format":"fmp-def/0.1","dependencies":[],"exports":{"forms":[{"id":"x86:example/form","path":"forms/example.json"}],"profiles":[],"types":[]},"package_format":"monasm-package/0.1","package_id":"monasm.x86.example","requires_capabilities":[],"target_identity":{"address_width":64,"byte_order":"little","enabled_extensions":[],"execution_mode":"64","isa_family":"x86","isa_variant":"x86-64"},"target_profile":"monasm.target.x86_64","version":"0.1.0"}"#;
/// The §7.0 fixture asset; a digest input, never a legal row (`read` rejects it).
pub const EXAMPLE_ASSET: &str = r#"{"form_id":"x86:example/form","template":"90"}"#;

/// A legal package declaration, built as canonical JSON so a test never depends
/// on hand-written spacing.
#[derive(Clone, Debug)]
pub struct ManifestFixture {
    pub package_id: String,
    pub version: String,
    pub definition_format: String,
    pub forms: Vec<(String, String)>,
    pub capabilities: Vec<String>,
    pub extensions: Vec<String>,
    pub legacy: Option<(String, String)>,
    pub dependencies: Vec<(String, String, String)>,
    pub include_reserved_assets: bool,
    /// The package's declared target. The family is not a whitelist: a test may
    /// set `loongarch` to show the family rule is equality.
    pub isa_family: String,
    pub isa_variant: String,
    pub execution_mode: String,
    pub byte_order: String,
    pub address_width: i128,
    /// A descriptive label; never compared with the spec's `profile_id`.
    pub target_profile: String,
    /// The `packages/<target>/...` directory segment.
    pub target_dir: String,
}

impl Default for ManifestFixture {
    fn default() -> Self {
        ManifestFixture {
            package_id: "monasm.x86.mov-register".to_string(),
            version: "0.1.0".to_string(),
            definition_format: "fmp-def/0.1".to_string(),
            forms: vec![
                (
                    "x86:mov/r64-rm/legacy".to_string(),
                    "forms/mov-r64-rm.json".to_string(),
                ),
                (
                    "x86:mov/rm-r64/legacy".to_string(),
                    "forms/mov-rm-r64.json".to_string(),
                ),
            ],
            capabilities: vec!["field-placement/v1".to_string()],
            extensions: Vec::new(),
            legacy: Some(("x86_64".to_string(), "0.1.0".to_string())),
            dependencies: Vec::new(),
            include_reserved_assets: true,
            isa_family: "x86".to_string(),
            isa_variant: "x86-64".to_string(),
            execution_mode: "64".to_string(),
            byte_order: "little".to_string(),
            address_width: 64,
            target_profile: "monasm.target.x86_64".to_string(),
            target_dir: "x86_64".to_string(),
        }
    }
}

impl ManifestFixture {
    pub fn with_forms(forms: &[(&str, &str)]) -> Self {
        ManifestFixture {
            forms: forms
                .iter()
                .map(|(id, path)| (id.to_string(), path.to_string()))
                .collect(),
            ..ManifestFixture::default()
        }
    }

    pub fn json(&self) -> Json {
        let forms = self
            .forms
            .iter()
            .map(|(id, path)| {
                Json::Object(vec![
                    ("id".to_string(), Json::Str(id.clone())),
                    ("path".to_string(), Json::Str(path.clone())),
                ])
            })
            .collect();
        let mut exports = vec![("forms".to_string(), Json::Array(forms))];
        if self.include_reserved_assets {
            exports.push(("profiles".to_string(), Json::Array(Vec::new())));
            exports.push(("types".to_string(), Json::Array(Vec::new())));
        }
        let dependencies = self
            .dependencies
            .iter()
            .map(|(id, version, digest)| {
                Json::Object(vec![
                    ("package_id".to_string(), Json::Str(id.clone())),
                    (
                        "source_package_digest".to_string(),
                        Json::Str(digest.clone()),
                    ),
                    ("version".to_string(), Json::Str(version.clone())),
                ])
            })
            .collect();
        let mut entries = vec![
            (
                "definition_format".to_string(),
                Json::Str(self.definition_format.clone()),
            ),
            ("dependencies".to_string(), Json::Array(dependencies)),
            ("exports".to_string(), Json::Object(exports)),
            (
                "package_format".to_string(),
                Json::Str("monasm-package/0.1".to_string()),
            ),
            ("package_id".to_string(), Json::Str(self.package_id.clone())),
            (
                "requires_capabilities".to_string(),
                Json::Array(
                    self.capabilities
                        .iter()
                        .map(|name| Json::Str(name.clone()))
                        .collect(),
                ),
            ),
            (
                "target_identity".to_string(),
                Json::Object(vec![
                    ("address_width".to_string(), Json::Int(self.address_width)),
                    ("byte_order".to_string(), Json::Str(self.byte_order.clone())),
                    (
                        "enabled_extensions".to_string(),
                        Json::Array(
                            self.extensions
                                .iter()
                                .map(|name| Json::Str(name.clone()))
                                .collect(),
                        ),
                    ),
                    (
                        "execution_mode".to_string(),
                        Json::Str(self.execution_mode.clone()),
                    ),
                    ("isa_family".to_string(), Json::Str(self.isa_family.clone())),
                    (
                        "isa_variant".to_string(),
                        Json::Str(self.isa_variant.clone()),
                    ),
                ]),
            ),
            (
                "target_profile".to_string(),
                Json::Str(self.target_profile.clone()),
            ),
            ("version".to_string(), Json::Str(self.version.clone())),
        ];
        if let Some((isa, version)) = &self.legacy {
            entries.push((
                "legacy_source".to_string(),
                Json::Object(vec![
                    ("isa".to_string(), Json::Str(isa.clone())),
                    ("version".to_string(), Json::Str(version.clone())),
                ]),
            ));
        }
        Json::Object(entries)
    }

    pub fn text(&self) -> String {
        String::from_utf8(canonical_bytes(&self.json())).expect("canonical JSON is UTF-8")
    }
}

/// Parse a JSON literal, panicking on a typo in the test itself.
pub fn json_of(text: &str) -> Json {
    json::parse(text.as_bytes()).expect("the fixture is valid JSON")
}

/// The repository root, derived from this crate's manifest directory.
pub fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A disposable directory tree. `Drop` removes it, including on a panicking test.
pub struct TempTree {
    root: PathBuf,
}

impl TempTree {
    pub fn new(label: &str) -> TempTree {
        let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!(
            "fmp-definition-{label}-{}-{unique}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create the temp root");
        TempTree { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create the parent directory");
        }
        std::fs::write(&path, bytes).expect("write the fixture file");
        path
    }

    pub fn remove(&self, relative: &str) {
        std::fs::remove_file(self.root.join(relative)).expect("remove the fixture file");
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The row bytes for a form id the fixtures know; anything else gets the §7.0
/// preimage asset, which is legal JSON but deliberately not a legal row.
pub fn row_for(id: &str) -> &'static str {
    match id {
        "x86:mov/r64-rm/legacy" => MOV_R64_RM,
        "x86:mov/rm-r64/legacy" => MOV_RM_R64,
        "x86:add/rm64-imm8/legacy" => ADD_RM64_IMM8,
        "x86:mov/r64-riprel32/legacy" => MOV_R64_RIPREL32,
        _ => EXAMPLE_ASSET,
    }
}

/// Write a package whose manifest is `value`, not `fixture.json()`.
///
/// The tests that need one field changed (a target mismatch, a pinned-version
/// swap) mutate the parsed value and write it back, so the rest of the document
/// stays byte-identical to the fixture.
pub fn write_package_value(tree: &TempTree, fixture: &ManifestFixture, value: &Json) -> String {
    let relative = format!(
        "packages/{}/{}/{}",
        fixture.target_dir, fixture.package_id, fixture.version
    );
    tree.write(&format!("{relative}/package.json"), &canonical_bytes(value));
    for (id, path) in &fixture.forms {
        tree.write(&format!("{relative}/{path}"), row_for(id).as_bytes());
    }
    relative
}

/// Write the two-row x86 package used by the loader tests.
pub fn write_package(tree: &TempTree, fixture: &ManifestFixture) -> String {
    write_package_value(tree, fixture, &fixture.json())
}

/// Copy one pinned definition into the tree, so `check_legacy` can read it from
/// a disposable root instead of the repository.
pub fn copy_definition(tree: &TempTree, isa: &str, version: &str) {
    let source = repository_root()
        .join("definitions")
        .join(isa)
        .join(format!("{version}.json"));
    let bytes = std::fs::read(&source).unwrap_or_else(|error| {
        panic!("read {}: {error}", source.display());
    });
    tree.write(&format!("definitions/{isa}/{version}.json"), &bytes);
}

/// The raw-byte hash of a file, in the bare form the evidence manifest records.
pub fn raw_sha256(bytes: &[u8]) -> String {
    fmp_model::canonical::sha256(&[bytes])
}

/// An `evidence/manifest.json` with a fixed shape: every path in `files` with
/// its recorded hash, one `NOTICE` source, and the given oracle status.
///
/// `files` is sorted here so a test can pass pairs in the order it reads them.
pub fn evidence_manifest(files: &[(String, String)], oracle_status: &str) -> String {
    let mut sorted: Vec<&(String, String)> = files.iter().collect();
    sorted.sort_by(|left, right| left.0.cmp(&right.0));
    let entries = sorted
        .iter()
        .map(|(path, hash)| format!("{{\"path\":{},\"sha256\":{}}}", quote(path), quote(hash)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"evidence_format\":\"monasm-evidence/0.1\",\"files\":[{}],\"oracle\":{{\"command\":\"manual\",\"skips\":[],\"status\":{}}},\"sources\":[{{\"note\":\"pinned rows\",\"path\":\"NOTICE\"}}]}}",
        entries,
        quote(oracle_status)
    )
}

/// A Rust-escaped literal is a JSON string for the ASCII in these fixtures.
fn quote(value: &str) -> String {
    format!("{value:?}")
}

/// `tests/cases.json` with no cases: a release-shaped file, not a coverage claim.
pub const DEFAULT_CASES: &str = "{\"cases\":[],\"cases_format\":\"monasm-cases/0.1\"}\n";
/// A `NOTICE` whose bytes are what the evidence manifest records.
pub const DEFAULT_NOTICE: &str = "MonAsm example package. SPDX-License-Identifier: Apache-2.0\n";

/// Write a release-ready package: manifest, rows, `NOTICE`, `tests/cases.json`
/// and an evidence manifest that lists and hashes all three.
pub fn write_release_package(tree: &TempTree, fixture: &ManifestFixture) -> String {
    write_release_package_with(tree, fixture, DEFAULT_CASES.as_bytes(), &[])
}

/// [`write_release_package`] with caller-supplied case bytes and extra evidence.
///
/// `extra` entries are written under the package and added to the evidence
/// manifest, so a test can change an evidence file and update its hash without
/// touching the form rows.
pub fn write_release_package_with(
    tree: &TempTree,
    fixture: &ManifestFixture,
    cases: &[u8],
    extra: &[(&str, &[u8])],
) -> String {
    let relative = write_package(tree, fixture);
    write_release_evidence(tree, &relative, cases, extra);
    relative
}

/// [`write_release_package_with`] with a manifest value that is not
/// `fixture.json()`, so one field can differ while the rest stays byte-identical.
pub fn write_release_package_value(
    tree: &TempTree,
    fixture: &ManifestFixture,
    value: &Json,
    cases: &[u8],
    extra: &[(&str, &[u8])],
) -> String {
    let relative = write_package_value(tree, fixture, value);
    write_release_evidence(tree, &relative, cases, extra);
    relative
}

fn write_release_evidence(tree: &TempTree, relative: &str, cases: &[u8], extra: &[(&str, &[u8])]) {
    let notice = DEFAULT_NOTICE.as_bytes();
    tree.write(&format!("{relative}/NOTICE"), notice);
    tree.write(&format!("{relative}/tests/cases.json"), cases);
    for (path, bytes) in extra {
        tree.write(&format!("{relative}/{path}"), bytes);
    }
    let mut files = vec![
        ("NOTICE".to_string(), raw_sha256(notice)),
        ("tests/cases.json".to_string(), raw_sha256(cases)),
    ];
    for (path, bytes) in extra {
        files.push(((*path).to_string(), raw_sha256(bytes)));
    }
    let manifest = evidence_manifest(&files, "manual-derivation");
    tree.write(
        &format!("{relative}/evidence/manifest.json"),
        manifest.as_bytes(),
    );
}

/// The repository-relative path a [`ManifestFixture`] is written to.
pub fn package_relative(fixture: &ManifestFixture) -> String {
    format!(
        "packages/{}/{}/{}",
        fixture.target_dir, fixture.package_id, fixture.version
    )
}

/// Load an already-written package and read its `source_package_digest`.
pub fn package_digest(tree: &TempTree, fixture: &ManifestFixture) -> String {
    let relative = package_relative(fixture);
    let package = fmp_definition::LoadedPackage::load(tree.root(), &relative)
        .unwrap_or_else(|error| panic!("load {relative}: {error}"));
    package.source_package_digest().to_string()
}

/// One `packages[]` entry of a spec.
#[derive(Clone, Debug)]
pub struct SpecEntryFixture {
    pub package_id: String,
    pub version: String,
    pub path: String,
    pub source_package_digest: String,
}

impl SpecEntryFixture {
    pub fn new(
        package_id: impl Into<String>,
        version: impl Into<String>,
        path: impl Into<String>,
        source_package_digest: impl Into<String>,
    ) -> SpecEntryFixture {
        SpecEntryFixture {
            package_id: package_id.into(),
            version: version.into(),
            path: path.into(),
            source_package_digest: source_package_digest.into(),
        }
    }

    /// The entry for a package that is already written and release-shaped.
    pub fn of(tree: &TempTree, fixture: &ManifestFixture) -> SpecEntryFixture {
        SpecEntryFixture {
            package_id: fixture.package_id.clone(),
            version: fixture.version.clone(),
            path: package_relative(fixture),
            source_package_digest: package_digest(tree, fixture),
        }
    }
}

/// A canonical `monasm-bundle-spec/0.1` fixture.
#[derive(Clone, Debug)]
pub struct SpecFixture {
    pub bundle_id: String,
    pub profile_id: String,
    pub namespace: String,
    pub version: String,
    pub definition_format: String,
    pub isa_family: String,
    pub isa_variant: String,
    pub execution_mode: String,
    pub byte_order: String,
    pub address_width: i128,
    pub extensions: Vec<String>,
    pub packages: Vec<SpecEntryFixture>,
}

impl SpecFixture {
    pub fn for_packages(packages: Vec<SpecEntryFixture>) -> SpecFixture {
        SpecFixture {
            bundle_id: "monasm.bundle.x86.h2".to_string(),
            profile_id: "monasm.target.x86_64".to_string(),
            namespace: "monasm.isa.x86".to_string(),
            version: "0.1.0-h2".to_string(),
            definition_format: "fmp-def/0.1".to_string(),
            isa_family: "x86".to_string(),
            isa_variant: "x86-64".to_string(),
            execution_mode: "64".to_string(),
            byte_order: "little".to_string(),
            address_width: 64,
            extensions: Vec::new(),
            packages,
        }
    }

    pub fn json(&self) -> Json {
        let packages = self
            .packages
            .iter()
            .map(|entry| {
                Json::Object(vec![
                    (
                        "package_id".to_string(),
                        Json::Str(entry.package_id.clone()),
                    ),
                    ("path".to_string(), Json::Str(entry.path.clone())),
                    (
                        "source_package_digest".to_string(),
                        Json::Str(entry.source_package_digest.clone()),
                    ),
                    ("version".to_string(), Json::Str(entry.version.clone())),
                ])
            })
            .collect();
        Json::Object(vec![
            (
                "bundle_format".to_string(),
                Json::Str("monasm-bundle-spec/0.1".to_string()),
            ),
            ("bundle_id".to_string(), Json::Str(self.bundle_id.clone())),
            (
                "definition_format".to_string(),
                Json::Str(self.definition_format.clone()),
            ),
            ("namespace".to_string(), Json::Str(self.namespace.clone())),
            ("packages".to_string(), Json::Array(packages)),
            (
                "target".to_string(),
                Json::Object(vec![
                    (
                        "identity".to_string(),
                        Json::Object(vec![
                            ("address_width".to_string(), Json::Int(self.address_width)),
                            ("byte_order".to_string(), Json::Str(self.byte_order.clone())),
                            (
                                "enabled_extensions".to_string(),
                                Json::Array(
                                    self.extensions
                                        .iter()
                                        .map(|name| Json::Str(name.clone()))
                                        .collect(),
                                ),
                            ),
                            (
                                "execution_mode".to_string(),
                                Json::Str(self.execution_mode.clone()),
                            ),
                            ("isa_family".to_string(), Json::Str(self.isa_family.clone())),
                            (
                                "isa_variant".to_string(),
                                Json::Str(self.isa_variant.clone()),
                            ),
                        ]),
                    ),
                    ("profile_id".to_string(), Json::Str(self.profile_id.clone())),
                ]),
            ),
            ("version".to_string(), Json::Str(self.version.clone())),
        ])
    }

    /// Write the spec at `bundles/specs/<bundle_id>.json` and return the path.
    pub fn write(&self, tree: &TempTree) -> String {
        let relative = format!("bundles/specs/{}.json", self.bundle_id);
        tree.write(&relative, &canonical_bytes(&self.json()));
        relative
    }
}

/// Replace an object member, keeping every other member byte-identical.
pub fn json_set(value: &Json, field: &str, replacement: Json) -> Json {
    match value {
        Json::Object(entries) => Json::Object(
            entries
                .iter()
                .map(|(name, value)| {
                    if name == field {
                        (name.clone(), replacement.clone())
                    } else {
                        (name.clone(), value.clone())
                    }
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Remove an object member.
pub fn json_without(value: &Json, field: &str) -> Json {
    match value {
        Json::Object(entries) => Json::Object(
            entries
                .iter()
                .filter(|(name, _)| name != field)
                .cloned()
                .collect(),
        ),
        other => other.clone(),
    }
}

/// A package fixture with an explicit identity, export list and capability set.
///
/// The capability set must equal what the rows derive (§1.2), so a caller that
/// picks a row with an `operand_value` slot passes `integer-domain/v1` too.
pub fn package_with(
    package_id: &str,
    forms: &[(&str, &str)],
    capabilities: &[&str],
) -> ManifestFixture {
    ManifestFixture {
        package_id: package_id.to_string(),
        forms: forms
            .iter()
            .map(|(id, path)| ((*id).to_string(), (*path).to_string()))
            .collect(),
        capabilities: capabilities
            .iter()
            .map(|name| (*name).to_string())
            .collect(),
        legacy: None,
        ..ManifestFixture::default()
    }
}

/// One `packages[]` entry as it appears for a bad-digest test.
pub fn entry_with_dummy_digest(package_id: &str, version: &str, path: &str) -> SpecEntryFixture {
    SpecEntryFixture::new(
        package_id,
        version,
        path,
        format!("sha256:{}", "0".repeat(64)),
    )
}

/// The canonical bytes of a spec fixture.
pub fn spec_bytes(spec: &SpecFixture) -> Vec<u8> {
    canonical_bytes(&spec.json())
}

/// Parse a spec fixture without writing it, so a rejection is the document's.
pub fn parse_spec(spec: &SpecFixture) -> Result<fmp_definition::Spec, fmp_definition::BuildError> {
    fmp_definition::Spec::parse(&spec_bytes(spec))
}

/// Parse and build a bundle from a fixture, with the default builder identity.
pub fn build_bundle(
    tree: &TempTree,
    spec: &SpecFixture,
) -> Result<fmp_definition::CheckedBundle, fmp_definition::BuildError> {
    let spec = parse_spec(spec)?;
    fmp_definition::CheckedBundle::build(tree.root(), &spec, fmp_definition::Builder::default())
}

/// The same, for tests whose fixture must build.
pub fn checked(tree: &TempTree, spec: &SpecFixture) -> fmp_definition::CheckedBundle {
    build_bundle(tree, spec).unwrap_or_else(|error| panic!("build bundle: {error}"))
}

/// Overwrite one declared form asset after the package was written.
///
/// The source digest is computed later, so a row changed here is the row the
/// digest names; the evidence manifest never lists form assets.
pub fn overwrite_row(tree: &TempTree, fixture: &ManifestFixture, path: &str, value: &Json) {
    let relative = package_relative(fixture);
    tree.write(&format!("{relative}/{path}"), &canonical_bytes(value));
}
