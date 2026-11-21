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
            BuildError::Io { path, detail } => write!(formatter, "{path:?}: {detail}"),
        }
    }
}

impl std::error::Error for BuildError {}
