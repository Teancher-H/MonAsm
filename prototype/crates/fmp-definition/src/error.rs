//! The builder's own rejection vocabulary (`ADR-0128` §11).
//!
//! Every variant is a *deterministic rejection* except [`BuildError::Io`], which
//! is the host/internal class. Exit 1 and 2 therefore follow from the variant,
//! not from a caller's choice: an unreadable file must not be reported as an
//! invalid package, and an invalid package must not look like a host failure.
//!
//! The variants carry the facts the ADR requires a rejection to name — the
//! declared value, the pointer, the budget that was crossed — because a
//! rejection a reader cannot act on is the silent repair of `INV-07` in another
//! form.

use std::fmt;

/// One package-layer rejection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// A builder-parsed document broke its closed shape. `document` names the
    /// artifact (`package.json`, `evidence/manifest.json`, …), `pointer` is the
    /// JSON Pointer of the offending value and `reason` is the finding.
    ///
    /// This is the ADR's "manifest shape (required/optional keys)" class (§11)
    /// and covers an unknown, missing or duplicated key, a wrong JSON type, and
    /// a `*_format` string this version does not interpret. The last is a shape
    /// finding on purpose: a later format version is not a document this reader
    /// may guess at (`INV-01`).
    DocumentShape {
        document: &'static str,
        pointer: String,
        reason: String,
    },
    /// A dotted identifier, version or profile label broke §1.3's grammar.
    IdentifierLexical {
        field: &'static str,
        value: String,
        reason: &'static str,
    },
    /// A declared path broke §1.3's path grammar or its portability rules.
    PathLexical {
        field: &'static str,
        value: String,
        reason: &'static str,
    },
    /// `target_identity.enabled_extensions` is not strictly increasing.
    ExtensionLexical { value: String },
    /// `requires_capabilities` is not strictly increasing.
    CapabilityLexical { value: String },
    /// A capability string outside the table of §1.2.
    UnsupportedCapability { value: String },
    /// The declared capability set differs from the derived one (§1.2).
    CapabilityMismatch {
        declared: Vec<String>,
        derived: Vec<String>,
    },
    /// `exports.forms` is empty; `monasm-package/0.1` has no zero-form package.
    EmptyPackage,
    /// A non-empty reserved asset list under `monasm-package/0.1` (§5).
    UnsupportedAsset { kind: &'static str },
    /// A path leaves its root, or a component on it cannot be opened safely.
    PathEscape { path: String, reason: &'static str },
    /// An opened leaf is not a regular file (FIFO, socket, device, directory).
    NotARegularFile { path: String },
    /// The `<version>` path component disagrees with the manifest (§1).
    PathVersionMismatch { component: String, version: String },
    /// A size, count or depth budget of §12 was crossed.
    ResourceLimit { budget: &'static str, limit: u64 },
    /// A release-ready package is missing a required evidence item (§7.1).
    EvidenceIncomplete { missing: &'static str },
    /// A listed evidence file is absent, outside the package, or has the wrong
    /// hash (§7.0).
    EvidenceMismatch { path: String, reason: &'static str },
    /// A case's own `evidence` record is not listed, or does not match (§7.1).
    CaseEvidenceMismatch { path: String, reason: &'static str },
    /// A form row differs from the pinned legacy row it claims to migrate (§1).
    LegacyRowMismatch { form_id: String },
    /// The package's `target_identity` differs from its `legacy_source`'s.
    LegacyTargetMismatch { field: &'static str },
    /// A recorded digest differs from the one recomputed from the same bytes
    /// (§7, §8.2). It covers a spec entry naming a different package source and a
    /// sealed bundle whose own identity no longer matches its contents.
    DigestMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    /// One `package_id` appears at two versions in a spec (§4).
    VersionConflict {
        package_id: String,
        versions: Vec<String>,
    },
    /// A dependency edge is outside the closure, disagrees with the listed
    /// digest, or forms a cycle (§4, §8).
    DependencyMismatch {
        package_id: String,
        version: String,
        reason: &'static str,
    },
    /// A spec reuses a standalone or frozen legacy definition name (§2.1, §8).
    ReservedIdentity {
        namespace: String,
        version: String,
        reason: &'static str,
    },
    /// A form's ISA family differs from the package target's `isa_family` (§4.2).
    FormFamilyMismatch {
        form_id: String,
        family: String,
        target: String,
    },
    /// A form's `requires_extensions` is outside the package's declared cover
    /// (§4.1).
    FormExtensionMismatch {
        form_id: String,
        package_id: String,
        required: Vec<String>,
        declared: Vec<String>,
    },
    /// An `fmp-def/0.1` bundle selects a different target set from a package's
    /// declared cover, even when the package cover is a subset (§4.1).
    H2ExactTarget {
        package_id: String,
        declared: Vec<String>,
        selected: Vec<String>,
    },
    /// A package's structural target facts disagree with the bundle's (§4).
    TargetMismatch {
        package_id: String,
        field: &'static str,
    },
    /// Two packages export the same `form_id` (§5).
    OwnerConflict {
        form_id: String,
        first: String,
        second: String,
    },
    /// A sealed bundle's `form_owners` is missing a row, repeats one, names an
    /// absent form, or names a package outside `packages` (§8.2).
    BundleOwnerIncomplete {
        subject: String,
        reason: &'static str,
    },
    /// An artifact file name does not equal its `bundle_id` (§8.2).
    BundleFileMismatch {
        artifact: &'static str,
        expected: String,
        actual: String,
    },
    /// Two live specs share a `bundle_id` (§8).
    BundleIdConflict { bundle_id: String },
    /// Two live specs share a `(namespace, version)` (§8).
    DefinitionIdentityConflict { namespace: String, version: String },
    /// The per-closure byte budget of §12.2 was crossed.
    AggregateLimit { limit: u64 },
    /// `fmp_model::definition::read` refused a document the builder generated
    /// (§9). The underlying diagnostic text is preserved.
    DefinitionRejected { detail: String },
    /// A file could not be opened or read. Exit 2: the content may be valid.
    Io { path: String, detail: String },
}

impl BuildError {
    /// The stable name of the rejection. This is what a report prints; it is not
    /// an `fmp/0.1` diagnostic code (`ADR-0128` §11).
    pub fn code(&self) -> &'static str {
        match self {
            BuildError::DocumentShape { .. } => "document-shape",
            BuildError::IdentifierLexical { .. } => "identifier-lexical",
            BuildError::PathLexical { .. } => "path-lexical",
            BuildError::ExtensionLexical { .. } => "extension-lexical",
            BuildError::CapabilityLexical { .. } => "capability-lexical",
            BuildError::UnsupportedCapability { .. } => "unsupported-capability",
            BuildError::CapabilityMismatch { .. } => "capability-mismatch",
            BuildError::EmptyPackage => "empty-package",
            BuildError::UnsupportedAsset { .. } => "unsupported-asset",
            BuildError::PathEscape { .. } => "path-escape",
            BuildError::NotARegularFile { .. } => "not-a-regular-file",
            BuildError::PathVersionMismatch { .. } => "path-version-mismatch",
            BuildError::ResourceLimit { .. } => "resource-limit",
            BuildError::EvidenceIncomplete { .. } => "evidence-incomplete",
            BuildError::EvidenceMismatch { .. } => "evidence-mismatch",
            BuildError::CaseEvidenceMismatch { .. } => "case-evidence-mismatch",
            BuildError::LegacyRowMismatch { .. } => "legacy-row-mismatch",
            BuildError::LegacyTargetMismatch { .. } => "legacy-target-mismatch",
            BuildError::DigestMismatch { .. } => "digest-mismatch",
            BuildError::VersionConflict { .. } => "version-conflict",
            BuildError::DependencyMismatch { .. } => "dependency-mismatch",
            BuildError::ReservedIdentity { .. } => "reserved-identity",
            BuildError::FormFamilyMismatch { .. } => "form-family-mismatch",
            BuildError::FormExtensionMismatch { .. } => "form-extension-mismatch",
            BuildError::H2ExactTarget { .. } => "h2-exact-target",
            BuildError::TargetMismatch { .. } => "target-mismatch",
            BuildError::OwnerConflict { .. } => "owner-conflict",
            BuildError::BundleOwnerIncomplete { .. } => "bundle-owner-incomplete",
            BuildError::BundleFileMismatch { .. } => "bundle-file-mismatch",
            BuildError::BundleIdConflict { .. } => "bundle-id-conflict",
            BuildError::DefinitionIdentityConflict { .. } => "definition-identity-conflict",
            BuildError::AggregateLimit { .. } => "aggregate-limit",
            BuildError::DefinitionRejected { .. } => "definition-rejected",
            BuildError::Io { .. } => "host-io",
        }
    }

    /// `ADR-0128` §11: deterministic rejections exit 1, host and internal
    /// findings exit 2.
    pub fn exit_code(&self) -> i32 {
        match self {
            BuildError::Io { .. } => 2,
            _ => 1,
        }
    }

    pub(crate) fn shape(
        document: &'static str,
        pointer: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        BuildError::DocumentShape {
            document,
            pointer: pointer.into(),
            reason: reason.into(),
        }
    }

    pub(crate) fn io(path: &str, detail: impl fmt::Display) -> Self {
        BuildError::Io {
            path: path.to_string(),
            detail: detail.to_string(),
        }
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::DocumentShape {
                document,
                pointer,
                reason,
            } => write!(formatter, "{document} at {pointer:?}: {reason}"),
            BuildError::IdentifierLexical {
                field,
                value,
                reason,
            } => write!(formatter, "{field} {value:?}: {reason}"),
            BuildError::PathLexical {
                field,
                value,
                reason,
            } => write!(formatter, "{field} {value:?}: {reason}"),
            BuildError::ExtensionLexical { value } => write!(
                formatter,
                "enabled_extensions must be strictly increasing and duplicate-free, got {value:?}"
            ),
            BuildError::CapabilityLexical { value } => write!(
                formatter,
                "requires_capabilities must be strictly increasing and duplicate-free, got {value:?}"
            ),
            BuildError::UnsupportedCapability { value } => {
                write!(formatter, "unknown capability {value:?}")
            }
            BuildError::CapabilityMismatch { declared, derived } => write!(
                formatter,
                "requires_capabilities {declared:?} differs from the derived set {derived:?}"
            ),
            BuildError::EmptyPackage => {
                write!(formatter, "exports.forms is empty; no package can be built")
            }
            BuildError::UnsupportedAsset { kind } => {
                write!(formatter, "{kind} assets are reserved and must be empty")
            }
            BuildError::PathEscape { path, reason } => write!(formatter, "{path:?}: {reason}"),
            BuildError::NotARegularFile { path } => {
                write!(formatter, "{path:?} is not a regular file")
            }
            BuildError::PathVersionMismatch { component, version } => write!(
                formatter,
                "path component {component:?} disagrees with manifest version {version:?}"
            ),
            BuildError::ResourceLimit { budget, limit } => {
                write!(formatter, "{budget} exceeds the limit of {limit}")
            }
            BuildError::EvidenceIncomplete { missing } => {
                write!(formatter, "release evidence is missing {missing}")
            }
            BuildError::EvidenceMismatch { path, reason } => {
                write!(formatter, "evidence {path:?}: {reason}")
            }
            BuildError::CaseEvidenceMismatch { path, reason } => {
                write!(formatter, "case evidence {path:?}: {reason}")
            }
            BuildError::LegacyRowMismatch { form_id } => {
                write!(formatter, "{form_id:?} differs from its pinned legacy row")
            }
            BuildError::LegacyTargetMismatch { field } => {
                write!(formatter, "target_identity.{field} differs from legacy_source")
            }
            BuildError::DigestMismatch {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "{field} records {expected:?}, but the same bytes recompute to {actual:?}"
            ),
            BuildError::VersionConflict {
                package_id,
                versions,
            } => write!(
                formatter,
                "package_id {package_id:?} is listed at versions {versions:?}; at most one version may appear"
            ),
            BuildError::DependencyMismatch {
                package_id,
                version,
                reason,
            } => write!(formatter, "dependency {package_id}:{version}: {reason}"),
            BuildError::ReservedIdentity {
                namespace,
                version,
                reason,
            } => write!(
                formatter,
                "definition identity ({namespace:?}, {version:?}) is reserved: {reason}"
            ),
            BuildError::FormFamilyMismatch {
                form_id,
                family,
                target,
            } => write!(
                formatter,
                "form {form_id:?} has ISA family {family:?}, but the package target is {target:?}"
            ),
            BuildError::FormExtensionMismatch {
                form_id,
                package_id,
                required,
                declared,
            } => write!(
                formatter,
                "form {form_id:?} of package {package_id:?} requires {required:?}, outside the declared cover {declared:?}"
            ),
            BuildError::H2ExactTarget {
                package_id,
                declared,
                selected,
            } => write!(
                formatter,
                "package {package_id:?} declares {declared:?}, but an fmp-def/0.1 bundle must select exactly that set, not {selected:?}"
            ),
            BuildError::TargetMismatch { package_id, field } => write!(
                formatter,
                "package {package_id:?} disagrees with the bundle on {field}"
            ),
            BuildError::OwnerConflict {
                form_id,
                first,
                second,
            } => write!(
                formatter,
                "form {form_id:?} is exported by both {first:?} and {second:?}"
            ),
            BuildError::BundleOwnerIncomplete { subject, reason } => {
                write!(formatter, "form_owners {subject}: {reason}")
            }
            BuildError::BundleFileMismatch {
                artifact,
                expected,
                actual,
            } => write!(
                formatter,
                "{artifact} file name {actual:?} does not match bundle_id ({expected:?})"
            ),
            BuildError::BundleIdConflict { bundle_id } => write!(
                formatter,
                "two live specs share bundle_id {bundle_id:?}"
            ),
            BuildError::DefinitionIdentityConflict {
                namespace,
                version,
            } => write!(
                formatter,
                "two specs share definition identity ({namespace:?}, {version:?})"
            ),
            BuildError::AggregateLimit { limit } => {
                write!(formatter, "package-root bytes exceed the closure limit of {limit}")
            }
            BuildError::DefinitionRejected { detail } => write!(
                formatter,
                "fmp_model::definition::read rejected the generated document: {detail}"
            ),
            BuildError::Io { path, detail } => write!(formatter, "{path:?}: {detail}"),
        }
    }
}

impl std::error::Error for BuildError {}
