//! `bundles/specs/<bundle_id>.json`: the author's explicit closure (`ADR-0128`
//! §4, §4.1, §8.2).
//!
//! The spec is the complete package list, not a set of roots. The reader opens
//! exactly the declared paths and never scans a package directory, so an
//! unselected or corrupt package cannot change an old build (`HE-AC-05`).
//!
//! Three spellings are rejected rather than normalised: an array that is not
//! strictly increasing by `(package_id, version)`, two entries with the same
//! `path`, and one `package_id` at two versions. The builder never re-sorts an
//! alternate spelling into legality.

use std::collections::BTreeSet;
use std::path::Path;

use fmp_model::bind::{self, Fault, Obj};
use fmp_model::json::{self, Json};

use crate::budget::{self, Counter};
use crate::error::BuildError;
use crate::manifest::{self, TargetIdentity};

/// The only bundle-spec format this builder interprets.
pub const SPEC_FORMAT: &str = "monasm-bundle-spec/0.1";

const SPEC_FIELDS: &[&str] = &[
    "bundle_format",
    "bundle_id",
    "target",
    "definition_format",
    "namespace",
    "version",
    "packages",
];
const TARGET_FIELDS: &[&str] = &["profile_id", "identity"];
const PACKAGE_FIELDS: &[&str] = &["package_id", "version", "path", "source_package_digest"];

/// The bundle-level target: a nominal label plus the six-key identity.
///
/// `profile_id` is descriptive. Compatibility is decided by `identity` alone
/// (§4.1), so two specs may use the same label with different identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub profile_id: String,
    pub identity: TargetIdentity,
}

impl Target {
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("identity".to_string(), self.identity.to_json()),
            ("profile_id".to_string(), Json::Str(self.profile_id.clone())),
        ])
    }
}

/// One listed package, exactly as the spec fixes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecPackage {
    pub package_id: String,
    pub version: String,
    /// Repository-root-relative directory.
    pub path: String,
    pub source_package_digest: String,
}

/// A parsed, checked spec.
#[derive(Clone, Debug)]
pub struct Spec {
    canonical: Json,
    bundle_id: String,
    target: Target,
    definition_format: String,
    namespace: String,
    version: String,
    packages: Vec<SpecPackage>,
}

impl Spec {
    /// Read and check one spec file.
    ///
    /// The name is checked after parsing, because the expected name is derived
    /// from the `bundle_id` inside the document.
    pub fn load(root: &Path, relative: &str) -> Result<Spec, BuildError> {
        let mut counter = Counter::new("spec bytes", budget::ARTIFACT_BYTES);
        let bytes = budget::read_regular(
            &root.join(relative),
            budget::ARTIFACT_BYTES,
            "spec bytes",
            &mut counter,
        )?;
        let spec = Spec::parse(&bytes)?;
        crate::artifact::check_spec(relative, &spec.bundle_id)?;
        Ok(spec)
    }

    /// Parse and check the bytes of a spec.
    pub fn parse(bytes: &[u8]) -> Result<Spec, BuildError> {
        budget::check_depth(bytes)?;
        let value =
            json::parse(bytes).map_err(|error| BuildError::shape("spec", "", error.reason()))?;
        Spec::from_json(value)
    }

    pub fn from_json(value: Json) -> Result<Spec, BuildError> {
        let root = Obj::new("", "spec", &value).map_err(spec_shape)?;
        root.closed(SPEC_FIELDS).map_err(spec_shape)?;

        let (bundle_format, path) = root.required("bundle_format").map_err(spec_shape)?;
        let bundle_format = bind::string(bundle_format, path).map_err(spec_shape)?;
        if bundle_format != SPEC_FORMAT {
            return Err(BuildError::shape(
                "spec",
                "/bundle_format",
                format!("{bundle_format:?} is not {SPEC_FORMAT}"),
            ));
        }

        let (bundle_id, path) = root.required("bundle_id").map_err(spec_shape)?;
        let bundle_id = identifier(bundle_id, path, "bundle_id")?;

        let (target, path) = root.required("target").map_err(spec_shape)?;
        let target = target_value(target, path)?;

        let (definition_format, path) = root.required("definition_format").map_err(spec_shape)?;
        let definition_format = bind::string(definition_format, path).map_err(spec_shape)?;
        if !manifest::DEFINITION_FORMATS.contains(&definition_format) {
            return Err(BuildError::shape(
                "spec",
                "/definition_format",
                format!(
                    "{definition_format:?} is not one of {}",
                    manifest::DEFINITION_FORMATS.join(", ")
                ),
            ));
        }

        let (namespace, path) = root.required("namespace").map_err(spec_shape)?;
        let namespace = bind::owned_string(namespace, path).map_err(spec_shape)?;
        let (version, path) = root.required("version").map_err(spec_shape)?;
        let version = bind::owned_string(version, path).map_err(spec_shape)?;
        // §2.1: the standalone identity is a development name and can never be a
        // bundle identity. The prefix check runs before the grammar, because
        // `standalone+<hex>` is not a legal release version and the reason a
        // reader needs is "reserved", not "bad version".
        check_reserved_prefix(&namespace, &version)?;
        let namespace = identifier_value(namespace, "namespace")?;
        let version = version_value(version, "version")?;

        let (packages, path) = root.required("packages").map_err(spec_shape)?;
        let packages = package_list(packages, path)?;
        let definition_format = definition_format.to_string();

        Ok(Spec {
            canonical: value,
            bundle_id,
            target,
            definition_format,
            namespace,
            version,
            packages,
        })
    }

    pub fn canonical(&self) -> &Json {
        &self.canonical
    }

    pub fn bundle_id(&self) -> &str {
        &self.bundle_id
    }

    pub fn target(&self) -> &Target {
        &self.target
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

    pub fn packages(&self) -> &[SpecPackage] {
        &self.packages
    }

    /// Reject a namespace/version that reuses a frozen legacy definition name.
    ///
    /// The reserved set is read from `<root>/definitions/*/*.json` on every run,
    /// in sorted path order. It is never written and never enters a digest; it
    /// only prevents two different execution-rule snapshots from answering to
    /// one definition name (§8).
    pub fn check_reserved(&self, root: &Path) -> Result<(), BuildError> {
        check_reserved_prefix(&self.namespace, &self.version)?;
        let reserved = reserved_identities(root)?;
        if reserved.contains(&(self.namespace.clone(), self.version.clone())) {
            return Err(BuildError::ReservedIdentity {
                namespace: self.namespace.clone(),
                version: self.version.clone(),
                reason: "the pair names a frozen definition under definitions/",
            });
        }
        Ok(())
    }
}

/// Refuse duplicate identities across a set of live specs (§8).
///
/// `bundle_id` is checked first: two specs that share it would make a directory
/// listing decide which release a consumer holds. `(namespace, version)` is the
/// definition name and is permanent, so a duplicate is a conflict even when the
/// generated digests would be equal.
pub fn check_spec_set(specs: &[Spec]) -> Result<(), BuildError> {
    let mut bundle_ids = BTreeSet::new();
    let mut identities = BTreeSet::new();
    for spec in specs {
        if !bundle_ids.insert(spec.bundle_id.clone()) {
            return Err(BuildError::BundleIdConflict {
                bundle_id: spec.bundle_id.clone(),
            });
        }
        if !identities.insert((spec.namespace.clone(), spec.version.clone())) {
            return Err(BuildError::DefinitionIdentityConflict {
                namespace: spec.namespace.clone(),
                version: spec.version.clone(),
            });
        }
    }
    Ok(())
}

/// The `(namespace, version)` pairs the frozen corpus already owns.
pub fn reserved_identities(root: &Path) -> Result<BTreeSet<(String, String)>, BuildError> {
    let definitions = root.join("definitions");
    let mut pairs = BTreeSet::new();
    let directories = match std::fs::read_dir(&definitions) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(pairs),
        Err(error) => return Err(BuildError::io(&definitions.display().to_string(), error)),
    };
    let mut files = Vec::new();
    for directory in directories {
        let directory =
            directory.map_err(|error| BuildError::io(&definitions.display().to_string(), error))?;
        if !directory.path().is_dir() {
            continue;
        }
        let entries = std::fs::read_dir(directory.path())
            .map_err(|error| BuildError::io(&directory.path().display().to_string(), error))?;
        for entry in entries {
            let entry = entry
                .map_err(|error| BuildError::io(&directory.path().display().to_string(), error))?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) == Some("json") {
                files.push(path);
            }
        }
    }
    files.sort();
    for path in files {
        let display = path.display().to_string();
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
        let value = json::parse(&bytes).map_err(|error| {
            BuildError::io(
                &display,
                format!("unreadable legacy definition: {}", error.reason()),
            )
        })?;
        let namespace = value.get("namespace").and_then(Json::as_str);
        let version = value.get("version").and_then(Json::as_str);
        let (Some(namespace), Some(version)) = (namespace, version) else {
            return Err(BuildError::io(
                &display,
                "a frozen definition has no namespace/version pair",
            ));
        };
        pairs.insert((namespace.to_string(), version.to_string()));
    }
    Ok(pairs)
}

fn check_reserved_prefix(namespace: &str, version: &str) -> Result<(), BuildError> {
    if namespace.starts_with("monasm.standalone.") {
        return Err(BuildError::ReservedIdentity {
            namespace: namespace.to_string(),
            version: version.to_string(),
            reason: "monasm.standalone. is the verify --package development identity",
        });
    }
    if version.starts_with("standalone+") {
        return Err(BuildError::ReservedIdentity {
            namespace: namespace.to_string(),
            version: version.to_string(),
            reason: "standalone+ is the verify --package development identity",
        });
    }
    Ok(())
}

fn target_value(value: &Json, path: String) -> Result<Target, BuildError> {
    parse_target(value, path, "spec")
}

/// The `{profile_id, identity}` parser shared by the spec, lock and sealed
/// bundle. `document` only changes the document name in a rejection.
pub(crate) fn parse_target(
    value: &Json,
    path: String,
    document: &'static str,
) -> Result<Target, BuildError> {
    let shape = |fault: Fault| shape_in(document, fault);
    let object = Obj::new(path, "target", value).map_err(shape)?;
    object.closed(TARGET_FIELDS).map_err(shape)?;
    let (profile_id, path) = object.required("profile_id").map_err(shape)?;
    let profile_id = bind::owned_string(profile_id, path).map_err(shape)?;
    if let Err(reason) = crate::lexical::ident(&profile_id) {
        return Err(BuildError::IdentifierLexical {
            field: "target.profile_id",
            value: profile_id,
            reason,
        });
    }
    let (identity, path) = object.required("identity").map_err(shape)?;
    let identity = manifest::parse_target_identity(identity, path, document)?;
    Ok(Target {
        profile_id,
        identity,
    })
}

fn package_list(value: &Json, path: String) -> Result<Vec<SpecPackage>, BuildError> {
    let items = bind::array(value, path.clone()).map_err(spec_shape)?;
    if items.is_empty() {
        return Err(BuildError::shape(
            "spec",
            path,
            "packages is the full closure and may not be empty",
        ));
    }
    if items.len() as u64 > budget::PACKAGES_PER_CLOSURE {
        return Err(BuildError::ResourceLimit {
            budget: "packages per closure",
            limit: budget::PACKAGES_PER_CLOSURE,
        });
    }
    let mut packages = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let item_path = bind::pointer_index(&path, index);
        let object = Obj::new(item_path, "spec package", item).map_err(spec_shape)?;
        object.closed(PACKAGE_FIELDS).map_err(spec_shape)?;
        let (package_id, id_path) = object.required("package_id").map_err(spec_shape)?;
        let package_id = identifier(package_id, id_path, "packages[].package_id")?;
        let (version, version_path) = object.required("version").map_err(spec_shape)?;
        let version = version_value(
            bind::owned_string(version, version_path).map_err(spec_shape)?,
            "packages[].version",
        )?;
        let (declared_path, path_path) = object.required("path").map_err(spec_shape)?;
        let declared_path = bind::owned_string(declared_path, path_path).map_err(spec_shape)?;
        budget::check_path_length("packages[].path", &declared_path)?;
        let (path_id, path_version) = crate::package::repository_components(&declared_path)?;
        if path_id != package_id {
            return Err(BuildError::PathLexical {
                field: "packages[].path",
                value: declared_path,
                reason: "the <package_id> component must equal packages[].package_id",
            });
        }
        if path_version != version {
            return Err(BuildError::PathVersionMismatch {
                component: path_version.to_string(),
                version: version.clone(),
            });
        }
        let (digest, digest_path) = object
            .required("source_package_digest")
            .map_err(spec_shape)?;
        let digest = bind::string(digest, digest_path).map_err(spec_shape)?;
        if !crate::digest::is_sha256_literal(digest) {
            return Err(BuildError::shape(
                "spec",
                object.child("source_package_digest"),
                "expected the literal sha256:<64 lowercase hex>",
            ));
        }
        packages.push(SpecPackage {
            package_id,
            version,
            path: declared_path,
            source_package_digest: digest.to_string(),
        });
    }

    // §8.2: two entries with the same `path` are rejected even when their content
    // is identical. This runs before the ordering rule so a repeated path is a
    // path finding, not an ordering shape error.
    for (index, package) in packages.iter().enumerate() {
        let folded = crate::lexical::fold(&package.path);
        for other in &packages[index + 1..] {
            if crate::lexical::fold(&other.path) == folded {
                return Err(BuildError::PathLexical {
                    field: "packages[].path",
                    value: other.path.clone(),
                    reason: "two spec entries fold to the same repository path",
                });
            }
        }
    }

    if !packages.windows(2).all(|pair| {
        (&pair[0].package_id, &pair[0].version) < (&pair[1].package_id, &pair[1].version)
    }) {
        return Err(BuildError::shape(
            "spec",
            path,
            "packages must be strictly sorted by (package_id, version)",
        ));
    }

    // At most one version of a package_id may appear, even when their exports are
    // disjoint (§4): the lock would otherwise record two owners for one release
    // identity.
    let mut index = 0;
    while index + 1 < packages.len() {
        if packages[index].package_id == packages[index + 1].package_id {
            return Err(BuildError::VersionConflict {
                package_id: packages[index].package_id.clone(),
                versions: vec![
                    packages[index].version.clone(),
                    packages[index + 1].version.clone(),
                ],
            });
        }
        index += 1;
    }
    Ok(packages)
}

fn identifier(value: &Json, path: String, field: &'static str) -> Result<String, BuildError> {
    let value = bind::owned_string(value, path).map_err(spec_shape)?;
    identifier_value(value, field)
}

fn identifier_value(value: String, field: &'static str) -> Result<String, BuildError> {
    if let Err(reason) = crate::lexical::ident(&value) {
        return Err(BuildError::IdentifierLexical {
            field,
            value,
            reason,
        });
    }
    Ok(value)
}

fn version_value(value: String, field: &'static str) -> Result<String, BuildError> {
    if let Err(reason) = crate::lexical::version(&value) {
        return Err(BuildError::IdentifierLexical {
            field,
            value,
            reason,
        });
    }
    Ok(value)
}

fn spec_shape(fault: Fault) -> BuildError {
    shape_in("spec", fault)
}

fn shape_in(document: &'static str, fault: Fault) -> BuildError {
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
    BuildError::shape(document, fault.path(), reason)
}
