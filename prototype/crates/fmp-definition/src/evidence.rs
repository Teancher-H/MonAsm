//! `evidence/manifest.json`: the audit trail of a package (`ADR-0128` §7.0/§7.1).
//!
//! The manifest is optional while a package is under development and required
//! once it is release-ready. It covers documentation, source records, oracle
//! records and case evidence — never a form, type or profile file, because those
//! enter the source digest instead. Its own bytes are what `evidence_digest`
//! hashes, so the audit trail is part of the release identity while the machine
//! definition stays untouched.
//!
//! Two hash rules are easy to get wrong and both are enforced here:
//!
//! - `files[].sha256` and a case's `evidence.sha256` are **bare** 64 lowercase
//!   hex characters, not the `sha256:` literal, and they hash *raw committed
//!   bytes*. A CRLF change, an indentation change or a trailing newline is a real
//!   change (§7.0).
//! - `evidence_digest` uses the `monasm-evidence/0.1` separator, so an evidence
//!   manifest and a package manifest with identical canonical bytes cannot share
//!   a digest.

use fmp_model::bind::{self, Fault, Obj};
use fmp_model::json::{self, Json};

use crate::budget;
use crate::digest;
use crate::error::BuildError;

/// The only evidence format this builder interprets.
pub const EVIDENCE_FORMAT: &str = "monasm-evidence/0.1";
/// The three `oracle.status` values of §7.0.
pub const ORACLE_STATUSES: [&str; 3] = ["reproduced", "manual-derivation", "not-applicable"];

const MANIFEST_FIELDS: &[&str] = &["evidence_format", "sources", "oracle", "files"];
const SOURCE_FIELDS: &[&str] = &["path", "note"];
const ORACLE_FIELDS: &[&str] = &["status", "command", "skips"];
const SKIP_FIELDS: &[&str] = &["case_id", "reason"];
const FILE_FIELDS: &[&str] = &["path", "sha256"];

/// Where an encoding fact came from, recorded as a checked-in file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    pub path: String,
    pub note: String,
}

/// One skipped case and the reason it is skipped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skip {
    pub case_id: String,
    pub reason: String,
}

/// The oracle record: what was run, or why it was not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Oracle {
    pub status: String,
    pub command: String,
    pub skips: Vec<Skip>,
}

/// One covered file with its raw-byte hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceFile {
    pub path: String,
    pub sha256: String,
}

/// A parsed, shape-checked evidence manifest.
#[derive(Clone, Debug)]
pub struct EvidenceManifest {
    canonical: Json,
    sources: Vec<Source>,
    oracle: Oracle,
    files: Vec<EvidenceFile>,
}

impl EvidenceManifest {
    pub fn parse(bytes: &[u8]) -> Result<EvidenceManifest, BuildError> {
        budget::check_depth(bytes)?;
        let value = json::parse(bytes)
            .map_err(|error| BuildError::shape("evidence/manifest.json", "", error.reason()))?;
        EvidenceManifest::from_json(value)
    }

    pub fn from_json(value: Json) -> Result<EvidenceManifest, BuildError> {
        let root = Obj::new("", "evidence manifest", &value).map_err(shape)?;
        root.closed(MANIFEST_FIELDS).map_err(shape)?;

        let (format, path) = root.required("evidence_format").map_err(shape)?;
        let format = bind::string(format, path).map_err(shape)?;
        if format != EVIDENCE_FORMAT {
            return Err(BuildError::shape(
                "evidence/manifest.json",
                "/evidence_format",
                format!("{format:?} is not {EVIDENCE_FORMAT}"),
            ));
        }

        let (sources, path) = root.required("sources").map_err(shape)?;
        let sources = source_list(sources, path)?;

        let (oracle, path) = root.required("oracle").map_err(shape)?;
        let oracle = oracle_record(oracle, path)?;

        let (files, path) = root.required("files").map_err(shape)?;
        let files = file_list(files, path)?;

        for source in &sources {
            if !files.iter().any(|file| file.path == source.path) {
                return Err(BuildError::shape(
                    "evidence/manifest.json",
                    "/sources",
                    format!("source {:?} is not listed in files", source.path),
                ));
            }
        }

        Ok(EvidenceManifest {
            canonical: value,
            sources,
            oracle,
            files,
        })
    }

    pub fn canonical(&self) -> &Json {
        &self.canonical
    }

    pub fn sources(&self) -> &[Source] {
        &self.sources
    }

    pub fn oracle(&self) -> &Oracle {
        &self.oracle
    }

    pub fn files(&self) -> &[EvidenceFile] {
        &self.files
    }

    pub fn digest(&self) -> String {
        digest::evidence_digest(&self.canonical)
    }

    /// The manifest-level half of §7.1's release requirements.
    ///
    /// The other half — every listed file exists inside the package and matches
    /// its recorded hash — needs the package root and is done by the loader. This
    /// method answers only what the document itself must say: the mandatory
    /// entries are listed, at least one source is recorded, and `oracle.status`
    /// is a value `monasm-package/0.1` can actually use.
    pub fn check_release_shape(&self, required: &[&'static str]) -> Result<(), BuildError> {
        for entry in required {
            if !self.files.iter().any(|file| file.path == *entry) {
                return Err(BuildError::EvidenceIncomplete { missing: entry });
            }
        }
        if self.sources.is_empty() {
            return Err(BuildError::EvidenceIncomplete {
                missing: "a sources entry",
            });
        }
        match self.oracle.status.as_str() {
            "reproduced" => {
                if self.oracle.command.is_empty() {
                    return Err(BuildError::EvidenceIncomplete {
                        missing: "an oracle.command for a reproduced oracle",
                    });
                }
            }
            "manual-derivation" => {
                if self.oracle.command.is_empty() {
                    return Err(BuildError::EvidenceIncomplete {
                        missing: "an oracle.command carrying the manual rationale",
                    });
                }
            }
            // `not-applicable` is reserved for a formless package, and
            // `monasm-package/0.1` has no formless package (§1). A later format
            // that admits one may admit it; this reader must not guess.
            "not-applicable" => {
                return Err(BuildError::EvidenceIncomplete {
                    missing: "a formless package for oracle.status not-applicable",
                });
            }
            other => {
                return Err(BuildError::shape(
                    "evidence/manifest.json",
                    "/oracle/status",
                    format!("{other:?} is not one of {}", ORACLE_STATUSES.join(", ")),
                ));
            }
        }
        for skip in &self.oracle.skips {
            if skip.case_id.is_empty() || skip.reason.is_empty() {
                return Err(BuildError::EvidenceIncomplete {
                    missing: "a case_id and reason for every oracle skip",
                });
            }
        }
        Ok(())
    }
}

fn source_list(value: &Json, path: String) -> Result<Vec<Source>, BuildError> {
    let items = bind::array(value, path.clone()).map_err(shape)?;
    let mut sources = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let item_path = bind::pointer_index(&path, index);
        let object = Obj::new(item_path, "source", item).map_err(shape)?;
        object.closed(SOURCE_FIELDS).map_err(shape)?;
        let path_value = field(&object, "path")?;
        evidence_path(&path_value)?;
        let note = field(&object, "note")?;
        sources.push(Source {
            path: path_value,
            note,
        });
    }
    if !sources.windows(2).all(|pair| pair[0].path < pair[1].path) {
        return Err(BuildError::shape(
            "evidence/manifest.json",
            path,
            "sources must be sorted strictly by path",
        ));
    }
    Ok(sources)
}

fn oracle_record(value: &Json, path: String) -> Result<Oracle, BuildError> {
    let object = Obj::new(path, "oracle", value).map_err(shape)?;
    object.closed(ORACLE_FIELDS).map_err(shape)?;
    let status = field(&object, "status")?;
    let command = field(&object, "command")?;
    let (skips, skips_path) = object.required("skips").map_err(shape)?;
    let items = bind::array(skips, skips_path.clone()).map_err(shape)?;
    let mut skip_list = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let item_path = bind::pointer_index(&skips_path, index);
        let skip = Obj::new(item_path, "skip", item).map_err(shape)?;
        skip.closed(SKIP_FIELDS).map_err(shape)?;
        skip_list.push(Skip {
            case_id: field(&skip, "case_id")?,
            reason: field(&skip, "reason")?,
        });
    }
    if !skip_list
        .windows(2)
        .all(|pair| pair[0].case_id < pair[1].case_id)
    {
        return Err(BuildError::shape(
            "evidence/manifest.json",
            skips_path,
            "skips must be sorted strictly by case_id",
        ));
    }
    Ok(Oracle {
        status,
        command,
        skips: skip_list,
    })
}

fn file_list(value: &Json, path: String) -> Result<Vec<EvidenceFile>, BuildError> {
    let items = bind::array(value, path.clone()).map_err(shape)?;
    if items.len() as u64 > budget::EVIDENCE_FILES {
        return Err(BuildError::ResourceLimit {
            budget: "evidence files per package",
            limit: budget::EVIDENCE_FILES,
        });
    }
    let mut files = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let item_path = bind::pointer_index(&path, index);
        let object = Obj::new(item_path, "file", item).map_err(shape)?;
        object.closed(FILE_FIELDS).map_err(shape)?;
        let file_path = field(&object, "path")?;
        evidence_path(&file_path)?;
        let sha256 = field(&object, "sha256")?;
        if !digest::is_bare_sha256(&sha256) {
            return Err(BuildError::shape(
                "evidence/manifest.json",
                object.child("sha256"),
                "expected 64 lowercase hex characters",
            ));
        }
        files.push(EvidenceFile {
            path: file_path,
            sha256,
        });
    }
    if !files.windows(2).all(|pair| pair[0].path < pair[1].path) {
        return Err(BuildError::shape(
            "evidence/manifest.json",
            path,
            "files must be sorted strictly by path",
        ));
    }
    Ok(files)
}

fn field(object: &Obj<'_>, name: &'static str) -> Result<String, BuildError> {
    let (value, path) = object.required(name).map_err(shape)?;
    bind::owned_string(value, path).map_err(shape)
}

/// An evidence path is checked against the same §1.3 grammar, but a violation is
/// `evidence-mismatch`, not `path-lexical`.
///
/// §7.0 names one rejection class for this document — "every listed file exists,
/// stays inside the package and matches its recorded hash; a mismatch is
/// `evidence-mismatch`" — so an escaping path here is that class. The lexical
/// check still runs before any open, which is what makes the rejection
/// deterministic rather than host-dependent.
fn evidence_path(value: &str) -> Result<(), BuildError> {
    if let Err(fault) = crate::lexical::path(value) {
        return Err(BuildError::EvidenceMismatch {
            path: value.to_string(),
            reason: fault.reason(),
        });
    }
    if value.len() as u64 > budget::PATH_BYTES {
        return Err(BuildError::ResourceLimit {
            budget: "evidence path bytes",
            limit: budget::PATH_BYTES,
        });
    }
    Ok(())
}

fn shape(fault: Fault) -> BuildError {
    let reason = match &fault {
        Fault::Missing { field, object, .. } => format!("{object} is missing `{field}`"),
        Fault::Unknown { field, object, .. } => format!("{object} has unknown field `{field}`"),
        Fault::Type {
            expected, found, ..
        } => format!("expected {expected}, found {found}"),
        Fault::Domain {
            required, found, ..
        } => format!("expected {required}, found {found}"),
    };
    BuildError::shape("evidence/manifest.json", fault.path(), reason)
}
