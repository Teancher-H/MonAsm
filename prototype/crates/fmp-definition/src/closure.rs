//! The explicit closure: read every listed package once, check the edges, merge,
//! and name the result (`ADR-0128` §4, §4.1, §5, §7, §9).
//!
//! A [`Closure`] is the only value that sees all selected packages. It loads
//! each declared path exactly once through [`LoadedPackage::load_counted`], so
//! the bytes that are hashed are the bytes that are read under the package's own
//! target and later merged. No step re-opens a package path.
//!
//! The order is part of the contract: form ⊆ package is checked before package ⊆
//! bundle, ownership conflicts are rejected before the merge, and the merged
//! document is read by `fmp_model::definition::read` — the builder never
//! constructs a `Definition` directly.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use fmp_model::canonical::canonical_bytes;
use fmp_model::definition::{self, Definition};
use fmp_model::json::Json;

use crate::budget::{self, ClosureCounter};
use crate::digest;
use crate::error::BuildError;
use crate::manifest::TargetIdentity;
use crate::package::LoadedPackage;
use crate::sealed::{self, FormOwner, SealedPackage};
use crate::spec::Spec;

/// One checked closure. Its digests are the values the lock and sealed bundle
/// record; no method re-reads a package or recomputes a digest from a path.
#[derive(Debug)]
pub struct Closure {
    spec: Spec,
    packages: Vec<LoadedPackage>,
    definition_value: Json,
    definition: Arc<Definition>,
    sealed_packages: Vec<SealedPackage>,
    form_owners: Vec<FormOwner>,
    bundle_metadata: Json,
    bundle_digest: String,
    release_metadata: Json,
    release_digest: String,
    package_root_bytes: u64,
}

impl Closure {
    /// Read, check and merge the closure the spec selects.
    ///
    /// A package selected by a spec is release-ready (§7.1), so the closure
    /// refuses to produce a lock for a package whose evidence is incomplete.
    pub fn build(root: &Path, spec: &Spec) -> Result<Closure, BuildError> {
        spec.check_reserved(root)?;

        let mut closure_counter = ClosureCounter::new();
        let mut packages = Vec::with_capacity(spec.packages().len());
        for entry in spec.packages() {
            let package = LoadedPackage::load_counted(root, &entry.path, &mut closure_counter)?;
            check_entry(entry, &package)?;
            packages.push(package);
        }
        check_closure_counts(&packages)?;
        check_dependencies(&packages)?;
        check_form_coverage(&packages)?;
        check_each_package_reads(spec, &packages)?;
        check_targets(spec, &packages)?;
        check_ownership(&packages)?;

        // §7.1: a lock exists only for a release-ready closure.
        for package in &packages {
            package.check_release_evidence()?;
        }

        let form_owners = owner_rows(&packages);
        let merged = merged_document(spec, &packages);
        let merged_bytes = canonical_bytes(&merged);
        let definition = definition::read(&merged_bytes).map_err(|diagnostic| {
            BuildError::DefinitionRejected {
                detail: diagnostic.message(),
            }
        })?;
        check_generated_identity(spec, &definition)?;
        let definition = Arc::new(definition);

        let sealed_packages = sealed_packages(&packages);
        let target = spec.target().to_json();
        let bundle_metadata = sealed::bundle_metadata(sealed::BundleMetadata {
            bundle_id: spec.bundle_id(),
            definition_format: spec.definition_format(),
            definition_digest: definition.digest(),
            namespace: definition.namespace(),
            version: definition.version(),
            target: &target,
            packages: &sealed_packages,
            form_owners: &form_owners,
        });
        let bundle_digest = digest::bundle_digest(&bundle_metadata);

        let release_metadata =
            release_metadata(spec, definition.digest(), &bundle_digest, &packages);
        let release_digest = digest::release_digest(&release_metadata);

        Ok(Closure {
            spec: spec.clone(),
            packages,
            definition_value: merged,
            definition,
            sealed_packages,
            form_owners,
            bundle_metadata,
            bundle_digest,
            release_metadata,
            release_digest,
            package_root_bytes: closure_counter.spent(),
        })
    }

    pub fn spec(&self) -> &Spec {
        &self.spec
    }

    pub fn packages(&self) -> &[LoadedPackage] {
        &self.packages
    }

    pub fn definition_value(&self) -> &Json {
        &self.definition_value
    }

    pub fn definition_digest(&self) -> &str {
        self.definition.digest()
    }

    pub fn bundle_metadata(&self) -> &Json {
        &self.bundle_metadata
    }

    pub fn bundle_digest(&self) -> &str {
        &self.bundle_digest
    }

    pub fn release_metadata(&self) -> &Json {
        &self.release_metadata
    }

    pub fn release_digest(&self) -> &str {
        &self.release_digest
    }

    pub fn form_owners(&self) -> &[FormOwner] {
        &self.form_owners
    }

    pub fn sealed_packages(&self) -> &[SealedPackage] {
        &self.sealed_packages
    }

    /// The package-root bytes the §12.2 counter charged for this run.
    pub fn package_root_bytes(&self) -> u64 {
        self.package_root_bytes
    }

    pub(crate) fn definition_arc(&self) -> Arc<Definition> {
        Arc::clone(&self.definition)
    }
}

fn check_entry(
    entry: &crate::spec::SpecPackage,
    package: &LoadedPackage,
) -> Result<(), BuildError> {
    if package.manifest().package_id() != entry.package_id {
        return Err(BuildError::PathLexical {
            field: "packages[].path",
            value: entry.path.clone(),
            reason: "the manifest package_id differs from packages[].package_id",
        });
    }
    if package.manifest().version() != entry.version {
        return Err(BuildError::PathVersionMismatch {
            component: entry.version.clone(),
            version: package.manifest().version().to_string(),
        });
    }
    if package.source_package_digest() != entry.source_package_digest {
        return Err(BuildError::DigestMismatch {
            field: "packages[].source_package_digest",
            expected: entry.source_package_digest.clone(),
            actual: package.source_package_digest().to_string(),
        });
    }
    Ok(())
}

fn check_closure_counts(packages: &[LoadedPackage]) -> Result<(), BuildError> {
    let mut assets = 0u64;
    let mut evidence_files = 0u64;
    for package in packages {
        assets += package.forms().len() as u64;
        if let Some(evidence) = package.evidence() {
            evidence_files += evidence.files().len() as u64;
        }
    }
    if assets > budget::ASSETS_PER_CLOSURE {
        return Err(BuildError::ResourceLimit {
            budget: "declared assets per closure",
            limit: budget::ASSETS_PER_CLOSURE,
        });
    }
    if evidence_files > budget::EVIDENCE_FILES_PER_CLOSURE {
        return Err(BuildError::ResourceLimit {
            budget: "evidence files per closure",
            limit: budget::EVIDENCE_FILES_PER_CLOSURE,
        });
    }
    Ok(())
}

/// Resolve every dependency edge inside the spec, detect cycles, then compare
/// the declared digests.
///
/// Presence and cycles are checked before the digest, so a cyclic spec names the
/// cycle rather than an arbitrary digest disagreement. No step scans a
/// directory: an edge outside `packages` is the rejection, never a trigger.
fn check_dependencies(packages: &[LoadedPackage]) -> Result<(), BuildError> {
    let mut by_identity: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for (index, package) in packages.iter().enumerate() {
        by_identity.insert(
            (
                package.manifest().package_id(),
                package.manifest().version(),
            ),
            index,
        );
    }

    for package in packages {
        for dependency in package.manifest().dependencies() {
            if !by_identity
                .contains_key(&(dependency.package_id.as_str(), dependency.version.as_str()))
            {
                return Err(BuildError::DependencyMismatch {
                    package_id: dependency.package_id.clone(),
                    version: dependency.version.clone(),
                    reason: "the dependency is not listed in the spec",
                });
            }
        }
    }

    let mut state = vec![0u8; packages.len()];
    for index in 0..packages.len() {
        visit(index, packages, &by_identity, &mut state, 0)?;
    }

    for package in packages {
        for dependency in package.manifest().dependencies() {
            let index = by_identity[&(dependency.package_id.as_str(), dependency.version.as_str())];
            let actual = packages[index].source_package_digest();
            if actual != dependency.source_package_digest {
                return Err(BuildError::DependencyMismatch {
                    package_id: dependency.package_id.clone(),
                    version: dependency.version.clone(),
                    reason: "the dependency's digest differs from the listed package source",
                });
            }
        }
    }
    Ok(())
}

fn visit(
    index: usize,
    packages: &[LoadedPackage],
    by_identity: &BTreeMap<(&str, &str), usize>,
    state: &mut [u8],
    depth: u64,
) -> Result<(), BuildError> {
    if depth > budget::DEPENDENCY_DEPTH {
        return Err(BuildError::ResourceLimit {
            budget: "dependency depth",
            limit: budget::DEPENDENCY_DEPTH,
        });
    }
    match state[index] {
        1 => {
            let package = &packages[index];
            return Err(BuildError::DependencyMismatch {
                package_id: package.manifest().package_id().to_string(),
                version: package.manifest().version().to_string(),
                reason: "the dependency edges form a cycle",
            });
        }
        2 => return Ok(()),
        _ => {}
    }
    state[index] = 1;
    for dependency in packages[index].manifest().dependencies() {
        let next = by_identity[&(dependency.package_id.as_str(), dependency.version.as_str())];
        visit(next, packages, by_identity, state, depth + 1)?;
    }
    state[index] = 2;
    Ok(())
}

/// `E_form(f) ⊆ E_package` for every exported form (§4.1).
///
/// The check runs before the bundle is consulted, so a package cannot become
/// legal because its bundle selected more extensions. For `fmp-def/0.1` the
/// form object has no requirement key and the relation is vacuous.
fn check_form_coverage(packages: &[LoadedPackage]) -> Result<(), BuildError> {
    for package in packages {
        let declared: BTreeSet<&str> = package
            .manifest()
            .target()
            .enabled_extensions
            .iter()
            .map(String::as_str)
            .collect();
        for form in package.forms() {
            let Some(requires) = form.value().get("requires_extensions") else {
                continue;
            };
            let Some(items) = requires.as_array() else {
                return Err(BuildError::shape(
                    "form asset",
                    form.declared().path.clone(),
                    "requires_extensions must be an array",
                ));
            };
            let mut required = Vec::with_capacity(items.len());
            for item in items {
                let Some(name) = item.as_str() else {
                    return Err(BuildError::shape(
                        "form asset",
                        form.declared().path.clone(),
                        "requires_extensions must contain strings",
                    ));
                };
                required.push(name.to_string());
            }
            if required
                .iter()
                .any(|name| !declared.contains(name.as_str()))
            {
                return Err(BuildError::FormExtensionMismatch {
                    form_id: form.declared().id.clone(),
                    package_id: package.manifest().package_id().to_string(),
                    required,
                    declared: package.manifest().target().enabled_extensions.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Build each package's own document under its own target and let
/// `fmp_model::definition::read` judge it (§4.1, §9).
fn check_each_package_reads(spec: &Spec, packages: &[LoadedPackage]) -> Result<(), BuildError> {
    for package in packages {
        let document = Json::Object(vec![
            (
                "definition_format".to_string(),
                Json::Str(package.manifest().definition_format().to_string()),
            ),
            (
                "forms".to_string(),
                Json::Array(package.form_values().into_iter().cloned().collect()),
            ),
            (
                "namespace".to_string(),
                Json::Str(spec.namespace().to_string()),
            ),
            (
                "target_identity".to_string(),
                package.manifest().target().to_json(),
            ),
            ("version".to_string(), Json::Str(spec.version().to_string())),
        ]);
        let bytes = canonical_bytes(&document);
        definition::read(&bytes).map_err(|diagnostic| BuildError::DefinitionRejected {
            detail: format!(
                "package {}: {}",
                package.manifest().package_id(),
                diagnostic.message()
            ),
        })?;
    }
    Ok(())
}

/// `definition_format` and the five structural identity fields must agree; the
/// extension set is a cover relation, with `fmp-def/0.1` keeping the
/// transitional equality (`h2-exact-target`).
fn check_targets(spec: &Spec, packages: &[LoadedPackage]) -> Result<(), BuildError> {
    let selected: BTreeSet<&str> = spec
        .target()
        .identity
        .enabled_extensions
        .iter()
        .map(String::as_str)
        .collect();
    for package in packages {
        let package_id = package.manifest().package_id().to_string();
        if package.manifest().definition_format() != spec.definition_format() {
            return Err(BuildError::TargetMismatch {
                package_id,
                field: "definition_format",
            });
        }
        if let Some(field) = spec
            .target()
            .identity
            .same_structure(package.manifest().target())
        {
            return Err(BuildError::TargetMismatch { package_id, field });
        }
        let declared = &package.manifest().target().enabled_extensions;
        if spec.definition_format() == "fmp-def/0.1" {
            if declared != &spec.target().identity.enabled_extensions {
                return Err(BuildError::H2ExactTarget {
                    package_id,
                    declared: declared.clone(),
                    selected: spec.target().identity.enabled_extensions.clone(),
                });
            }
        } else if !declared.iter().all(|name| selected.contains(name.as_str())) {
            return Err(BuildError::TargetMismatch {
                package_id,
                field: "enabled_extensions",
            });
        }
    }
    Ok(())
}

fn check_ownership(packages: &[LoadedPackage]) -> Result<(), BuildError> {
    let mut owners: BTreeMap<&str, &str> = BTreeMap::new();
    for package in packages {
        for form in package.forms() {
            let form_id = form.declared().id.as_str();
            let package_id = package.manifest().package_id();
            match owners.get(form_id) {
                Some(first) => {
                    return Err(BuildError::OwnerConflict {
                        form_id: form_id.to_string(),
                        first: (*first).to_string(),
                        second: package_id.to_string(),
                    });
                }
                None => {
                    owners.insert(form_id, package_id);
                }
            }
        }
    }
    Ok(())
}

fn owner_rows(packages: &[LoadedPackage]) -> Vec<FormOwner> {
    let mut owners: Vec<FormOwner> = packages
        .iter()
        .flat_map(|package| {
            package.forms().iter().map(move |form| FormOwner {
                form_id: form.declared().id.clone(),
                package_id: package.manifest().package_id().to_string(),
            })
        })
        .collect();
    owners.sort_by(|left, right| left.form_id.cmp(&right.form_id));
    owners
}

fn sealed_packages(packages: &[LoadedPackage]) -> Vec<SealedPackage> {
    packages
        .iter()
        .map(|package| SealedPackage {
            package_id: package.manifest().package_id().to_string(),
            version: package.manifest().version().to_string(),
            source_package_digest: package.source_package_digest().to_string(),
            enabled_extensions: package.manifest().target().enabled_extensions.clone(),
        })
        .collect()
}

fn merged_document(spec: &Spec, packages: &[LoadedPackage]) -> Json {
    let mut forms: Vec<&Json> = packages
        .iter()
        .flat_map(|package| package.forms().iter().map(|form| form.value()))
        .collect();
    forms.sort_by(|left, right| {
        let left = left.get("form_id").and_then(Json::as_str).unwrap_or("");
        let right = right.get("form_id").and_then(Json::as_str).unwrap_or("");
        left.cmp(right)
    });
    Json::Object(vec![
        (
            "definition_format".to_string(),
            Json::Str(spec.definition_format().to_string()),
        ),
        (
            "forms".to_string(),
            Json::Array(forms.into_iter().cloned().collect()),
        ),
        (
            "namespace".to_string(),
            Json::Str(spec.namespace().to_string()),
        ),
        (
            "target_identity".to_string(),
            spec.target().identity.to_json(),
        ),
        ("version".to_string(), Json::Str(spec.version().to_string())),
    ])
}

fn check_generated_identity(spec: &Spec, definition: &Definition) -> Result<(), BuildError> {
    if definition.namespace() != spec.namespace() || definition.version() != spec.version() {
        return Err(BuildError::DefinitionIdentityConflict {
            namespace: definition.namespace().to_string(),
            version: definition.version().to_string(),
        });
    }
    if definition.definition_format() != spec.definition_format() {
        return Err(BuildError::TargetMismatch {
            package_id: "bundle".to_string(),
            field: "definition_format",
        });
    }
    compare_target(&spec.target().identity, definition.target())
}

fn compare_target(
    expected: &TargetIdentity,
    actual: &definition::DefinitionTarget,
) -> Result<(), BuildError> {
    for (field, equal) in [
        ("isa_family", expected.isa_family == actual.isa_family),
        ("isa_variant", expected.isa_variant == actual.isa_variant),
        (
            "execution_mode",
            expected.execution_mode == actual.execution_mode,
        ),
        ("byte_order", expected.byte_order == actual.byte_order),
        (
            "address_width",
            expected.address_width == actual.address_width,
        ),
        (
            "enabled_extensions",
            expected.enabled_extensions == actual.enabled_extensions,
        ),
    ] {
        if !equal {
            return Err(BuildError::TargetMismatch {
                package_id: "bundle".to_string(),
                field,
            });
        }
    }
    Ok(())
}

fn release_metadata(
    spec: &Spec,
    definition_digest: &str,
    bundle_digest: &str,
    packages: &[LoadedPackage],
) -> Json {
    let entries = packages
        .iter()
        .map(|package| {
            let mut fields = vec![
                (
                    "package_id".to_string(),
                    Json::Str(package.manifest().package_id().to_string()),
                ),
                (
                    "source_package_digest".to_string(),
                    Json::Str(package.source_package_digest().to_string()),
                ),
                (
                    "version".to_string(),
                    Json::Str(package.manifest().version().to_string()),
                ),
            ];
            // §8.2: a development-shaped entry omits the key; a released one
            // carries it. The lock is only written for a release-ready closure,
            // so this branch is defensive, not a second publishing mode.
            if let Some(evidence_digest) = package.evidence_digest() {
                fields.push(("evidence_digest".to_string(), Json::Str(evidence_digest)));
            }
            Json::Object(fields)
        })
        .collect();
    Json::Object(vec![
        (
            "bundle_digest".to_string(),
            Json::Str(bundle_digest.to_string()),
        ),
        (
            "bundle_id".to_string(),
            Json::Str(spec.bundle_id().to_string()),
        ),
        (
            "definition_digest".to_string(),
            Json::Str(definition_digest.to_string()),
        ),
        ("packages".to_string(), Json::Array(entries)),
    ])
}
