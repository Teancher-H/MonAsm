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
                    ("address_width".to_string(), Json::Int(64)),
                    ("byte_order".to_string(), Json::Str("little".to_string())),
                    (
                        "enabled_extensions".to_string(),
                        Json::Array(
                            self.extensions
                                .iter()
                                .map(|name| Json::Str(name.clone()))
                                .collect(),
                        ),
                    ),
                    ("execution_mode".to_string(), Json::Str("64".to_string())),
                    ("isa_family".to_string(), Json::Str("x86".to_string())),
                    ("isa_variant".to_string(), Json::Str("x86-64".to_string())),
                ]),
            ),
            (
                "target_profile".to_string(),
                Json::Str("monasm.target.x86_64".to_string()),
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
    let relative = format!("packages/x86_64/{}/{}", fixture.package_id, fixture.version);
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
