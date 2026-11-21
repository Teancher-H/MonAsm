//! `bundles/locks/<bundle_id>.lock.json`: the lock is a closed object and a
//! receipt, not a definition (`ADR-0128` §8, §8.2).
//!
//! The lock is written only for a release-ready closure, so every package entry
//! carries `evidence_digest`. `builder` is the one field that is not compared by
//! `verify --all --check`; it is shape-checked and printed, and an absent build
//! identifier is an omitted key, never `null`.

use std::path::Path;

use fmp_model::bind::{self, Fault, Obj};
use fmp_model::json::{self, Json};

use crate::budget::{self, Counter};
use crate::error::BuildError;
use crate::spec::{self, Target};

/// The only lock format this builder interprets.
pub const LOCK_FORMAT: &str = "monasm-lock/0.1";

const LOCK_FIELDS: &[&str] = &[
    "lock_format",
    "bundle_id",
    "definition_format",
    "namespace",
    "version",
    "target",
    "bundle_digest",
    "definition_digest",
    "release_digest",
    "packages",
    "builder",
];
const PACKAGE_FIELDS: &[&str] = &[
    "package_id",
    "version",
    "path",
    "source_package_digest",
    "evidence_digest",
];
const BUILDER_FIELDS: &[&str] = &["name", "version", "build"];

/// One locked package entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockedPackage {
    pub package_id: String,
    pub version: String,
    pub path: String,
    pub source_package_digest: String,
    pub evidence_digest: String,
}

/// A parsed, shape-checked lock.
#[derive(Clone, Debug)]
pub struct Lock {
    canonical: Json,
    bundle_id: String,
    definition_format: String,
    namespace: String,
    version: String,
    target: Target,
    bundle_digest: String,
    definition_digest: String,
    release_digest: String,
    packages: Vec<LockedPackage>,
}

impl Lock {
    pub fn load(root: &Path, relative: &str) -> Result<Lock, BuildError> {
        let mut counter = Counter::new("lock bytes", budget::ARTIFACT_BYTES);
        let bytes = budget::read_regular(
            &root.join(relative),
            budget::ARTIFACT_BYTES,
            "lock bytes",
            &mut counter,
        )?;
        let lock = Lock::parse(&bytes)?;
        crate::artifact::check_lock(relative, &lock.bundle_id)?;
        Ok(lock)
    }

    pub fn parse(bytes: &[u8]) -> Result<Lock, BuildError> {
        budget::check_depth(bytes)?;
        let value =
            json::parse(bytes).map_err(|error| BuildError::shape("lock", "", error.reason()))?;
        Lock::from_json(value)
    }

    pub fn from_json(value: Json) -> Result<Lock, BuildError> {
        let root = Obj::new("", "lock", &value).map_err(lock_shape)?;
        root.closed(LOCK_FIELDS).map_err(lock_shape)?;

        let (format, path) = root.required("lock_format").map_err(lock_shape)?;
        let format = bind::string(format, path).map_err(lock_shape)?;
        if format != LOCK_FORMAT {
            return Err(BuildError::shape(
                "lock",
                "/lock_format",
                format!("{format:?} is not {LOCK_FORMAT}"),
            ));
        }

        let bundle_id = field_string(&root, "bundle_id")?;
        if let Err(reason) = crate::lexical::ident(&bundle_id) {
            return Err(BuildError::IdentifierLexical {
                field: "bundle_id",
                value: bundle_id,
                reason,
            });
        }
        let definition_format = field_string(&root, "definition_format")?;
        if !crate::manifest::DEFINITION_FORMATS.contains(&definition_format.as_str()) {
            return Err(BuildError::shape(
                "lock",
                "/definition_format",
                format!(
                    "{definition_format:?} is not one of {}",
                    crate::manifest::DEFINITION_FORMATS.join(", ")
                ),
            ));
        }
        let namespace = field_string(&root, "namespace")?;
        let version = field_string(&root, "version")?;
        let bundle_digest = digest_field(&root, "bundle_digest")?;
        let definition_digest = digest_field(&root, "definition_digest")?;
        let release_digest = digest_field(&root, "release_digest")?;

        let (target, path) = root.required("target").map_err(lock_shape)?;
        let target = spec::parse_target(target, path, "lock")?;

        let (packages, path) = root.required("packages").map_err(lock_shape)?;
        let packages = package_rows(packages, path)?;

        let (builder, path) = root.required("builder").map_err(lock_shape)?;
        let object = Obj::new(path, "builder", builder).map_err(lock_shape)?;
        object.closed(BUILDER_FIELDS).map_err(lock_shape)?;
        // The builder identity is recorded and shape-checked, never compared: it
        // is the one field a `--check` run may not require to be equal (§8.2).
        field_string(&object, "name")?;
        field_string(&object, "version")?;
        if let Some((build, path)) = object.optional("build") {
            let shape = |fault: Fault| lock_shape(fault);
            let build = bind::owned_string(build, path).map_err(shape)?;
            if build.is_empty() {
                return Err(BuildError::shape(
                    "lock",
                    object.child("build"),
                    "a present build identifier is not empty",
                ));
            }
        }

        Ok(Lock {
            canonical: value,
            bundle_id,
            definition_format,
            namespace,
            version,
            target,
            bundle_digest,
            definition_digest,
            release_digest,
            packages,
        })
    }

    pub fn canonical(&self) -> &Json {
        &self.canonical
    }

    pub fn bundle_id(&self) -> &str {
        &self.bundle_id
    }

    pub fn definition_format(&self) -> &str {
        &self.definition_format
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn target(&self) -> &Target {
        &self.target
    }

    pub fn bundle_digest(&self) -> &str {
        &self.bundle_digest
    }

    pub fn definition_digest(&self) -> &str {
        &self.definition_digest
    }

    pub fn release_digest(&self) -> &str {
        &self.release_digest
    }

    pub fn packages(&self) -> &[LockedPackage] {
        &self.packages
    }
}

fn package_rows(value: &Json, path: String) -> Result<Vec<LockedPackage>, BuildError> {
    let items = bind::array(value, path.clone()).map_err(lock_shape)?;
    let mut packages = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let item_path = bind::pointer_index(&path, index);
        let object = Obj::new(item_path, "locked package", item).map_err(lock_shape)?;
        object.closed(PACKAGE_FIELDS).map_err(lock_shape)?;
        let package_id = field_string(&object, "package_id")?;
        let version = field_string(&object, "version")?;
        let declared_path = field_string(&object, "path")?;
        let source_package_digest = digest_field(&object, "source_package_digest")?;
        let evidence_digest = digest_field(&object, "evidence_digest")?;
        packages.push(LockedPackage {
            package_id,
            version,
            path: declared_path,
            source_package_digest,
            evidence_digest,
        });
    }
    if !packages.windows(2).all(|pair| {
        (&pair[0].package_id, &pair[0].version) < (&pair[1].package_id, &pair[1].version)
    }) {
        return Err(BuildError::shape(
            "lock",
            path,
            "packages must be strictly sorted by (package_id, version)",
        ));
    }
    Ok(packages)
}

fn digest_field(object: &Obj<'_>, field: &'static str) -> Result<String, BuildError> {
    let value = field_string(object, field)?;
    if !crate::digest::is_sha256_literal(&value) {
        return Err(BuildError::shape(
            "lock",
            object.child(field),
            "expected the literal sha256:<64 lowercase hex>",
        ));
    }
    Ok(value)
}

fn field_string(object: &Obj<'_>, field: &'static str) -> Result<String, BuildError> {
    let (value, path) = object.required(field).map_err(lock_shape)?;
    bind::owned_string(value, path).map_err(lock_shape)
}

fn lock_shape(fault: Fault) -> BuildError {
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
    BuildError::shape("lock", fault.path(), reason)
}
