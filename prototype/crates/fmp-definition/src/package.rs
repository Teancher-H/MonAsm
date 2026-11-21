//! One package directory, read once, checked, and given its own digests
//! (`ADR-0128` §1, §7.0, §9).
//!
//! A [`LoadedPackage`] is the single in-memory value the rest of the builder
//! consumes: the canonical manifest, the declared asset values and the digest of
//! exactly the bytes they were parsed from. There is no method that re-opens a
//! declared path, because that is the failure this type exists to make
//! impossible: hash buffer A, merge buffer B, and the lock attests a source the
//! definition never contained.
//!
//! The reader is the *trusted-tree* reader. It opens ordinary paths, so a link on
//! the path is followed; it does check the file type on the opened handle and
//! charges every byte it reads against the §12 budgets. The no-follow guarantee,
//! and with it any publication claim, belongs to the publication channel and is
//! gated on the three-platform PoC.

use std::collections::BTreeSet;
use std::path::Path;

use fmp_model::canonical::{canonical_bytes, sha256};
use fmp_model::json::{self, Json};

use crate::budget::{self, Counter};
use crate::digest::{self, Asset, AssetKind};
use crate::error::BuildError;
use crate::evidence::EvidenceManifest;
use crate::manifest::{self, DeclaredAsset, Manifest, TargetIdentity};

/// A form asset: the declaration, the parsed object, and the digest of the bytes
/// it was parsed from.
#[derive(Clone, Debug)]
pub struct LoadedForm {
    declared: DeclaredAsset,
    value: Json,
    digest: String,
}

impl LoadedForm {
    pub fn declared(&self) -> &DeclaredAsset {
        &self.declared
    }

    pub fn value(&self) -> &Json {
        &self.value
    }

    /// `sha256(canonical(asset))`: the entry a source record names.
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// The package path split into the components §1.3 fixes.
struct Components<'a> {
    package_id: &'a str,
    version: &'a str,
}

impl<'a> Components<'a> {
    fn parse(relative: &'a str) -> Result<Components<'a>, BuildError> {
        if let Err(fault) = crate::lexical::path(relative) {
            return Err(BuildError::PathLexical {
                field: "packages[].path",
                value: relative.to_string(),
                reason: fault.reason(),
            });
        }
        let segments: Vec<&str> = relative.split('/').collect();
        if segments.len() != 4 || segments[0] != "packages" {
            return Err(BuildError::PathLexical {
                field: "packages[].path",
                value: relative.to_string(),
                reason: "a package path is packages/<target>/<package_id>/<version>",
            });
        }
        Ok(Components {
            package_id: segments[2],
            version: segments[3],
        })
    }
}

/// A package as loaded: one read per file, one digest per read.
#[derive(Clone, Debug)]
pub struct LoadedPackage {
    relative: String,
    manifest: Manifest,
    forms: Vec<LoadedForm>,
    evidence: Option<EvidenceManifest>,
    cases: Option<Vec<u8>>,
    source_package_digest: String,
}

impl LoadedPackage {
    /// Read a package from `<root>/<relative>`.
    ///
    /// Order follows §12: lexical validation of the declared path, then the open
    /// and the type check on the opened handle, then the bounded read, then the
    /// parse. Nothing is opened that the manifest did not declare — the package
    /// root is not scanned.
    pub fn load(root: &Path, relative: &str) -> Result<LoadedPackage, BuildError> {
        let components = Components::parse(relative)?;
        budget::check_path_length("packages[].path", relative)?;
        let directory = root.join(relative);

        let mut counter = Counter::package();
        let manifest_bytes = budget::read_regular(
            &directory.join("package.json"),
            budget::MANIFEST_BYTES,
            "manifest bytes",
            &mut counter,
        )?;
        let manifest = Manifest::parse(&manifest_bytes)?;

        if components.package_id != manifest.package_id() {
            return Err(BuildError::PathLexical {
                field: "packages[].path",
                value: relative.to_string(),
                reason: "the <package_id> component must equal the full package_id",
            });
        }
        if components.version != manifest.version() {
            return Err(BuildError::PathVersionMismatch {
                component: components.version.to_string(),
                version: manifest.version().to_string(),
            });
        }
        if manifest.forms().len() as u64 > budget::FORMS_PER_PACKAGE {
            return Err(BuildError::ResourceLimit {
                budget: "exported forms per package",
                limit: budget::FORMS_PER_PACKAGE,
            });
        }

        let mut forms = Vec::with_capacity(manifest.forms().len());
        for declared in manifest.forms() {
            let path = directory.join(&declared.path);
            let bytes =
                budget::read_regular(&path, budget::ASSET_BYTES, "form asset bytes", &mut counter)?;
            budget::check_depth(&bytes)?;
            let value = json::parse(&bytes).map_err(|error| {
                BuildError::shape("form asset", declared.path.clone(), error.reason())
            })?;
            let digest = digest::asset_digest(&value);
            forms.push(LoadedForm {
                declared: declared.clone(),
                value,
                digest,
            });
        }

        // §1.2: the derivation runs before any merge, so a declaration that omits
        // a primitive is rejected before the rows are read as a definition.
        let values: Vec<&Json> = forms.iter().map(|form| &form.value).collect();
        let derived = manifest::derive_capabilities(&values);
        manifest::check_capabilities(manifest.requires_capabilities(), &derived)?;

        let assets: Vec<Asset> = forms
            .iter()
            .map(|form| Asset {
                kind: AssetKind::Form,
                path: form.declared.path.clone(),
                digest: form.digest.clone(),
            })
            .collect();
        let source_package_digest = digest::source_package_digest(manifest.canonical(), &assets);

        let (evidence, cases) = load_evidence(&directory)?;

        Ok(LoadedPackage {
            relative: relative.to_string(),
            manifest,
            forms,
            evidence,
            cases,
            source_package_digest,
        })
    }

    /// The repository-root-relative directory, as declared.
    pub fn relative(&self) -> &str {
        &self.relative
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn forms(&self) -> &[LoadedForm] {
        &self.forms
    }

    pub fn form_values(&self) -> Vec<&Json> {
        self.forms.iter().map(|form| &form.value).collect()
    }

    /// `sha256(b"monasm-package/0.1" ++ 0x00 ++ canonical(record))`.
    pub fn source_package_digest(&self) -> &str {
        &self.source_package_digest
    }

    pub fn evidence(&self) -> Option<&EvidenceManifest> {
        self.evidence.as_ref()
    }

    /// `evidence_digest` is present exactly when an evidence manifest was read.
    pub fn evidence_digest(&self) -> Option<String> {
        self.evidence.as_ref().map(EvidenceManifest::digest)
    }

    /// The §7.1 release requirements that the document itself must satisfy.
    ///
    /// A development package may omit the manifest entirely; a release-ready one
    /// may not, and the difference is a rejection named `evidence-incomplete`,
    /// never a silent downgrade. When a manifest is present it is authoritative
    /// in both modes, but the two facts that need the package root — every listed
    /// file exists and matches, and every case evidence reference is listed —
    /// were already established at load time, so they are not re-read here.
    pub fn check_release_evidence(&self) -> Result<(), BuildError> {
        let Some(evidence) = &self.evidence else {
            return Err(BuildError::EvidenceIncomplete {
                missing: "evidence/manifest.json",
            });
        };
        evidence.check_release_shape(&["NOTICE", "tests/cases.json"])?;
        if self.cases.is_none() {
            return Err(BuildError::EvidenceIncomplete {
                missing: "tests/cases.json",
            });
        }
        Ok(())
    }

    /// Compare this package with the pinned legacy definition it claims to
    /// migrate (`ADR-0128` §1).
    ///
    /// The pinned file is read once and both comparisons consume that one value:
    /// the target identity (as a **set** of extensions, because the frozen corpus
    /// has its own spelling) and every form row (as **canonical** bytes, so a
    /// reindented but equal row is equal).
    ///
    /// A package without `legacy_source` is a new package: it is verified from its
    /// own target and cases, and there is nothing to compare here.
    pub fn check_legacy(&self, root: &Path) -> Result<(), BuildError> {
        let Some(source) = self.manifest.legacy_source() else {
            return Ok(());
        };
        let path = root.join(source.relative_path());
        let mut counter = Counter::new(
            "pinned legacy definition bytes",
            budget::LEGACY_DEFINITION_BYTES,
        );
        let bytes = budget::read_regular(
            &path,
            budget::LEGACY_DEFINITION_BYTES,
            "pinned legacy definition bytes",
            &mut counter,
        )?;
        budget::check_depth(&bytes)?;
        let legacy = json::parse(&bytes)
            .map_err(|error| BuildError::shape("legacy definition", "", error.reason()))?;

        compare_target(&legacy, self.manifest.target())?;

        let rows = legacy
            .get("forms")
            .and_then(Json::as_array)
            .ok_or_else(|| {
                BuildError::shape(
                    "legacy definition",
                    "/forms",
                    "the pinned definition has no forms array",
                )
            })?;
        for form in &self.forms {
            let row = rows
                .iter()
                .find(|row| row.get("form_id").and_then(Json::as_str) == Some(&form.declared.id))
                .ok_or_else(|| BuildError::LegacyRowMismatch {
                    form_id: form.declared.id.clone(),
                })?;
            if canonical_bytes(row) != canonical_bytes(&form.value) {
                return Err(BuildError::LegacyRowMismatch {
                    form_id: form.declared.id.clone(),
                });
            }
        }
        Ok(())
    }
}

/// Read and verify `evidence/manifest.json` if it exists.
///
/// A present manifest is authoritative even in development mode: every listed
/// file must exist inside the package and match its recorded raw-byte hash, and
/// every case-level `evidence` reference must resolve to a listed file with the
/// same hash (`ADR-0128` §7.1). The cases bytes are kept because the release
/// check has to consume the same bytes that were verified, not a second read of
/// the same path.
fn load_evidence(
    directory: &Path,
) -> Result<(Option<EvidenceManifest>, Option<Vec<u8>>), BuildError> {
    let mut counter = Counter::evidence();
    let bytes = budget::read_optional(
        &directory.join("evidence").join("manifest.json"),
        budget::EVIDENCE_MANIFEST_BYTES,
        "evidence manifest bytes",
        &mut counter,
    )?;
    let Some(bytes) = bytes else {
        return Ok((None, None));
    };
    let manifest = EvidenceManifest::parse(&bytes)?;
    let mut cases = None;
    for file in manifest.files() {
        let path = directory.join(&file.path);
        let bytes = budget::read_optional(
            &path,
            budget::EVIDENCE_BYTES,
            "evidence file bytes",
            &mut counter,
        )?
        .ok_or_else(|| BuildError::EvidenceMismatch {
            path: file.path.clone(),
            reason: "a listed file is missing",
        })?;
        let actual = sha256(&[&bytes]);
        if actual != file.sha256 {
            return Err(BuildError::EvidenceMismatch {
                path: file.path.clone(),
                reason: "the raw-byte hash differs from the recorded one",
            });
        }
        if file.path == "tests/cases.json" {
            cases = Some(bytes);
        }
    }
    if let Some(cases) = &cases {
        for (path, recorded) in case_evidence(cases)? {
            match manifest.files().iter().find(|file| file.path == path) {
                None => {
                    return Err(BuildError::CaseEvidenceMismatch {
                        path,
                        reason: "the case's evidence file is not listed in the manifest",
                    });
                }
                Some(file) if file.sha256 != recorded => {
                    return Err(BuildError::CaseEvidenceMismatch {
                        path,
                        reason: "the case's evidence.sha256 differs from the listed hash",
                    });
                }
                Some(_) => {}
            }
        }
    }
    Ok((Some(manifest), cases))
}

/// The `(path, sha256)` pairs a cases file records.
///
/// This is a shallow scan on purpose: the case contract — format version, stages,
/// coverage, mutation rules — is the conformance layer's job, not this node's.
/// What is read here is only what the evidence set must contain.
fn case_evidence(cases: &[u8]) -> Result<Vec<(String, String)>, BuildError> {
    budget::check_depth(cases)?;
    let document = json::parse(cases)
        .map_err(|error| BuildError::shape("tests/cases.json", "", error.reason()))?;
    let mut references = Vec::new();
    let Some(items) = document.get("cases").and_then(Json::as_array) else {
        return Ok(references);
    };
    for item in items {
        let Some(evidence) = item.get("evidence").and_then(Json::as_object) else {
            continue;
        };
        let path = evidence
            .iter()
            .find(|(key, _)| key == "path")
            .and_then(|(_, value)| value.as_str());
        let digest = evidence
            .iter()
            .find(|(key, _)| key == "sha256")
            .and_then(|(_, value)| value.as_str());
        if let (Some(path), Some(digest)) = (path, digest) {
            references.push((path.to_string(), digest.to_string()));
        }
    }
    Ok(references)
}

fn compare_target(legacy: &Json, target: &TargetIdentity) -> Result<(), BuildError> {
    let identity = legacy.get("target_identity").ok_or_else(|| {
        BuildError::shape(
            "legacy definition",
            "/target_identity",
            "the pinned definition has no target_identity",
        )
    })?;
    for (field, expected) in [
        ("isa_family", &target.isa_family),
        ("isa_variant", &target.isa_variant),
        ("execution_mode", &target.execution_mode),
        ("byte_order", &target.byte_order),
    ] {
        let actual = identity.get(field).and_then(Json::as_str);
        if actual != Some(expected.as_str()) {
            return Err(BuildError::LegacyTargetMismatch { field });
        }
    }
    let actual = identity.get("address_width").and_then(Json::as_i128);
    if actual != Some(target.address_width as i128) {
        return Err(BuildError::LegacyTargetMismatch {
            field: "address_width",
        });
    }
    // The frozen corpus keeps its published spelling, so extensions are compared
    // as sets (`ADR-0128` §1.1, `TargetEq`).
    let declared: BTreeSet<&str> = target
        .enabled_extensions
        .iter()
        .map(String::as_str)
        .collect();
    let mut legacy_extensions = BTreeSet::new();
    if let Some(items) = identity.get("enabled_extensions").and_then(Json::as_array) {
        for item in items {
            let Some(name) = item.as_str() else {
                return Err(BuildError::LegacyTargetMismatch {
                    field: "enabled_extensions",
                });
            };
            legacy_extensions.insert(name);
        }
    }
    if declared != legacy_extensions {
        return Err(BuildError::LegacyTargetMismatch {
            field: "enabled_extensions",
        });
    }
    Ok(())
}
