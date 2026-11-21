//! `package.json`: one closed manifest per package directory (`ADR-0128` §1).
//!
//! The manifest is the only entry point. It declares the package identity, its
//! own execution target, its capability requirement, its dependencies and the
//! exact set of files it exports — so ownership, the source digest and the
//! closure are all facts of this document rather than of a directory scan.
//!
//! Two rules shape the code:
//!
//! - **The declared capability set must equal the derived one** (§1.2). A
//!   declaration that omits a primitive the rows use lets a later consumer
//!   under-provision; a declaration that lists an unused one turns the field into
//!   a wish list. `field-placement/v1` is derived by every legal `fmp-def/0.1`
//!   form (a form has slots, a slot has placements), so a package with forms
//!   cannot declare `[]`.
//! - **A flat set has one legal spelling** (§1). `requires_capabilities` and
//!   `target_identity.enabled_extensions` are strictly increasing; a reversed or
//!   duplicated array is a format rejection, never sorted into legality. Without
//!   that rule two documents with the same set would have different source
//!   digests, and "the same extension set" would have no unique representation.

use fmp_model::bind::{self, Fault, Obj};
use fmp_model::json::{self, Json};

use crate::budget;
use crate::error::BuildError;

/// The only package format this builder interprets.
pub const PACKAGE_FORMAT: &str = "monasm-package/0.1";
/// Row formats a manifest may name. `fmp-def/0.2` is a row format, not a
/// package format: the package still declares which one its files use.
pub const DEFINITION_FORMATS: [&str; 2] = ["fmp-def/0.1", "fmp-def/0.2"];

/// Derived when some exported form places a value at a bit offset (§1.2).
pub const CAPABILITY_FIELD_PLACEMENT: &str = "field-placement/v1";
/// Derived when some slot encodes an integer operand under its range (§1.2).
pub const CAPABILITY_INTEGER_DOMAIN: &str = "integer-domain/v1";
/// The capability table of §1.2. H3 may extend it; it may not weaken equality.
pub const CAPABILITIES: [&str; 2] = [CAPABILITY_FIELD_PLACEMENT, CAPABILITY_INTEGER_DOMAIN];

const MANIFEST_FIELDS: &[&str] = &[
    "package_format",
    "package_id",
    "version",
    "target_profile",
    "definition_format",
    "target_identity",
    "legacy_source",
    "requires_capabilities",
    "dependencies",
    "exports",
];
const TARGET_FIELDS: &[&str] = &[
    "isa_family",
    "isa_variant",
    "execution_mode",
    "enabled_extensions",
    "byte_order",
    "address_width",
];
const EXPORT_FIELDS: &[&str] = &["forms", "types", "profiles"];
const ASSET_FIELDS: &[&str] = &["id", "path"];
const DEPENDENCY_FIELDS: &[&str] = &["package_id", "version", "source_package_digest"];
const LEGACY_FIELDS: &[&str] = &["isa", "version"];

/// A package's own declaration of its execution target (§2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetIdentity {
    pub isa_family: String,
    pub isa_variant: String,
    pub execution_mode: String,
    pub enabled_extensions: Vec<String>,
    pub byte_order: String,
    pub address_width: u32,
}

/// Migration provenance: which pinned legacy definition the rows came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacySource {
    pub isa: String,
    pub version: String,
}

impl LegacySource {
    /// `definitions/<isa>/<version>.json`, relative to the repository root.
    pub fn relative_path(&self) -> String {
        format!("definitions/{}/{}.json", self.isa, self.version)
    }
}

/// One closed dependency entry (§1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dependency {
    pub package_id: String,
    pub version: String,
    /// The dependency's `source_package_digest`, not a definition or bundle one.
    pub source_package_digest: String,
}

/// One `{id, path}` declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredAsset {
    pub id: String,
    pub path: String,
}

/// A parsed, shape-checked manifest.
#[derive(Clone, Debug)]
pub struct Manifest {
    canonical: Json,
    package_id: String,
    version: String,
    target_profile: String,
    definition_format: String,
    target: TargetIdentity,
    legacy_source: Option<LegacySource>,
    requires_capabilities: Vec<String>,
    dependencies: Vec<Dependency>,
    forms: Vec<DeclaredAsset>,
    types: Vec<DeclaredAsset>,
    profiles: Vec<DeclaredAsset>,
}

impl Manifest {
    /// Parse and check one manifest.
    ///
    /// The depth budget is applied before parsing because the parser descends
    /// recursively; every other rule is applied to the parsed value.
    pub fn parse(bytes: &[u8]) -> Result<Manifest, BuildError> {
        budget::check_depth(bytes)?;
        let value = json::parse(bytes)
            .map_err(|error| BuildError::shape("package.json", "", error.reason()))?;
        Manifest::from_json(value)
    }

    /// Check an already-parsed manifest value.
    pub fn from_json(value: Json) -> Result<Manifest, BuildError> {
        let root = Obj::new("", "manifest", &value).map_err(manifest_shape)?;
        root.closed(MANIFEST_FIELDS).map_err(manifest_shape)?;

        let (package_format, path) = root.required("package_format").map_err(manifest_shape)?;
        let package_format = bind::string(package_format, path).map_err(manifest_shape)?;
        if package_format != PACKAGE_FORMAT {
            return Err(BuildError::shape(
                "package.json",
                "/package_format",
                format!("{package_format:?} is not {PACKAGE_FORMAT}"),
            ));
        }

        let (package_id, path) = root.required("package_id").map_err(manifest_shape)?;
        let package_id = identifier(package_id, path, "package_id")?;

        let (version, path) = root.required("version").map_err(manifest_shape)?;
        let version = self::version(version, path, "version")?;

        let (target_profile, path) = root.required("target_profile").map_err(manifest_shape)?;
        let target_profile = identifier(target_profile, path, "target_profile")?;

        let (definition_format, path) =
            root.required("definition_format").map_err(manifest_shape)?;
        let definition_format = bind::string(definition_format, path).map_err(manifest_shape)?;
        if !DEFINITION_FORMATS.contains(&definition_format) {
            return Err(BuildError::shape(
                "package.json",
                "/definition_format",
                format!(
                    "{definition_format:?} is not one of {}",
                    DEFINITION_FORMATS.join(", ")
                ),
            ));
        }
        let definition_format = definition_format.to_string();

        let (target, path) = root.required("target_identity").map_err(manifest_shape)?;
        let target = target_identity(target, path)?;

        let legacy_source = match root.optional("legacy_source") {
            Some((value, path)) => Some(legacy_source(value, path)?),
            None => None,
        };

        let (capabilities, path) = root
            .required("requires_capabilities")
            .map_err(manifest_shape)?;
        let requires_capabilities = capability_declaration(capabilities, path)?;

        let (dependencies, path) = root.required("dependencies").map_err(manifest_shape)?;
        let dependencies = dependency_list(dependencies, path)?;

        let (exports, path) = root.required("exports").map_err(manifest_shape)?;
        let exports = exports_object(exports, path)?;

        Ok(Manifest {
            canonical: value,
            package_id,
            version,
            target_profile,
            definition_format,
            target,
            legacy_source,
            requires_capabilities,
            dependencies,
            forms: exports.forms,
            types: exports.types,
            profiles: exports.profiles,
        })
    }

    /// The manifest value exactly as declared, for the source record. Optional
    /// keys that were absent stay absent, so `"types": []` and no `types` key
    /// are two different snapshots with different digests.
    pub fn canonical(&self) -> &Json {
        &self.canonical
    }

    pub fn package_id(&self) -> &str {
        &self.package_id
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn target_profile(&self) -> &str {
        &self.target_profile
    }

    pub fn definition_format(&self) -> &str {
        &self.definition_format
    }

    pub fn target(&self) -> &TargetIdentity {
        &self.target
    }

    pub fn legacy_source(&self) -> Option<&LegacySource> {
        self.legacy_source.as_ref()
    }

    pub fn requires_capabilities(&self) -> &[String] {
        &self.requires_capabilities
    }

    pub fn dependencies(&self) -> &[Dependency] {
        &self.dependencies
    }

    pub fn forms(&self) -> &[DeclaredAsset] {
        &self.forms
    }

    pub fn types(&self) -> &[DeclaredAsset] {
        &self.types
    }

    pub fn profiles(&self) -> &[DeclaredAsset] {
        &self.profiles
    }
}

/// The capability set a package's exported forms actually need (§1.2).
///
/// The derivation is over the form objects as declared: a non-empty `placements`
/// array on any slot derives `field-placement/v1`, and `from: "operand_value"`
/// derives `integer-domain/v1`. It runs before the rows are merged or read, so a
/// declaration that omits a primitive is rejected before any `read` — and a form
/// that `read` would reject (no slots at all) derives the empty set here rather
/// than being silently credited with a capability.
///
/// The result is sorted under code-point order, which is the only legal
/// spelling, so it can be compared with the declaration element by element.
pub fn derive_capabilities(forms: &[&Json]) -> Vec<String> {
    let mut placement = false;
    let mut integer = false;
    for form in forms {
        let Some(slots) = form.get("slots").and_then(Json::as_array) else {
            continue;
        };
        for slot in slots {
            if let Some(placements) = slot.get("placements").and_then(Json::as_array) {
                if !placements.is_empty() {
                    placement = true;
                }
            }
            if slot.get("from").and_then(Json::as_str) == Some("operand_value") {
                integer = true;
            }
        }
    }
    let mut derived = Vec::new();
    if placement {
        derived.push(CAPABILITY_FIELD_PLACEMENT.to_string());
    }
    if integer {
        derived.push(CAPABILITY_INTEGER_DOMAIN.to_string());
    }
    derived
}

/// Require the declaration to equal the derivation (§1.2), in both directions.
///
/// The comparison is over members: the declaration was already restricted to the
/// one strictly increasing spelling, so a set difference here is a semantic
/// finding (`capability-mismatch`), never a spelling one.
pub fn check_capabilities(declared: &[String], derived: &[String]) -> Result<(), BuildError> {
    if declared == derived {
        return Ok(());
    }
    Err(BuildError::CapabilityMismatch {
        declared: declared.to_vec(),
        derived: derived.to_vec(),
    })
}

struct Exports {
    forms: Vec<DeclaredAsset>,
    types: Vec<DeclaredAsset>,
    profiles: Vec<DeclaredAsset>,
}

fn exports_object(value: &Json, path: String) -> Result<Exports, BuildError> {
    let object = Obj::new(path, "exports", value).map_err(manifest_shape)?;
    object.closed(EXPORT_FIELDS).map_err(manifest_shape)?;
    let (forms, path) = object.required("forms").map_err(manifest_shape)?;
    let forms = asset_list(forms, path, "exports.forms")?;
    if forms.is_empty() {
        return Err(BuildError::EmptyPackage);
    }
    let types = optional_assets(&object, "types")?;
    let profiles = optional_assets(&object, "profiles")?;
    if !types.is_empty() {
        return Err(BuildError::UnsupportedAsset { kind: "type" });
    }
    if !profiles.is_empty() {
        return Err(BuildError::UnsupportedAsset { kind: "profile" });
    }
    Ok(Exports {
        forms,
        types,
        profiles,
    })
}

fn optional_assets(
    object: &Obj<'_>,
    field: &'static str,
) -> Result<Vec<DeclaredAsset>, BuildError> {
    match object.optional(field) {
        Some((value, path)) => asset_list(
            value,
            path,
            match field {
                "types" => "exports.types",
                _ => "exports.profiles",
            },
        ),
        None => Ok(Vec::new()),
    }
}

fn asset_list(
    value: &Json,
    path: String,
    field: &'static str,
) -> Result<Vec<DeclaredAsset>, BuildError> {
    let items = bind::array(value, path.clone()).map_err(manifest_shape)?;
    if items.len() as u64 > budget::ASSETS_PER_PACKAGE {
        return Err(BuildError::ResourceLimit {
            budget: "declared assets per package",
            limit: budget::ASSETS_PER_PACKAGE,
        });
    }
    let mut assets = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let item_path = bind::pointer_index(&path, index);
        let object = Obj::new(item_path, "asset", item).map_err(manifest_shape)?;
        object.closed(ASSET_FIELDS).map_err(manifest_shape)?;
        let (id, id_path) = object.required("id").map_err(manifest_shape)?;
        let id = bind::owned_string(id, id_path).map_err(manifest_shape)?;
        let (declared, path_value) = object.required("path").map_err(manifest_shape)?;
        let declared = bind::owned_string(declared, path_value).map_err(manifest_shape)?;
        declared_path(field, &declared)?;
        assets.push(DeclaredAsset { id, path: declared });
    }
    // Strictly increasing by `id` is the one legal order (§1). A reordering is a
    // different document, so it is rejected rather than canonicalised.
    if !assets.windows(2).all(|pair| pair[0].id < pair[1].id) {
        return Err(BuildError::shape(
            "package.json",
            path,
            format!("{field} must be sorted strictly by id"),
        ));
    }
    check_path_collisions(field, &assets)?;
    Ok(assets)
}

/// Two declared paths that differ only by case or by a trailing character would
/// be two names on ext4 and one file on APFS/NTFS (§1.3). The fold is the stated
/// reason, not "the file happened to open".
fn check_path_collisions(field: &'static str, assets: &[DeclaredAsset]) -> Result<(), BuildError> {
    for (index, asset) in assets.iter().enumerate() {
        let folded = crate::lexical::fold(&asset.path);
        for other in &assets[index + 1..] {
            if crate::lexical::fold(&other.path) == folded {
                return Err(BuildError::PathLexical {
                    field,
                    value: other.path.clone(),
                    reason: "two declared paths fold to the same name",
                });
            }
        }
    }
    Ok(())
}

fn dependency_list(value: &Json, path: String) -> Result<Vec<Dependency>, BuildError> {
    let items = bind::array(value, path.clone()).map_err(manifest_shape)?;
    let mut dependencies = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let item_path = bind::pointer_index(&path, index);
        let object = Obj::new(item_path, "dependency", item).map_err(manifest_shape)?;
        object.closed(DEPENDENCY_FIELDS).map_err(manifest_shape)?;
        let (package_id, id_path) = object.required("package_id").map_err(manifest_shape)?;
        let package_id = identifier(package_id, id_path, "dependencies[].package_id")?;
        let (version, version_path) = object.required("version").map_err(manifest_shape)?;
        let version = self::version(version, version_path, "dependencies[].version")?;
        let (digest, digest_path) = object
            .required("source_package_digest")
            .map_err(manifest_shape)?;
        let digest = bind::string(digest, digest_path).map_err(manifest_shape)?;
        if !crate::digest::is_sha256_literal(digest) {
            return Err(BuildError::shape(
                "package.json",
                object.child("source_package_digest"),
                "expected the literal sha256:<64 lowercase hex>",
            ));
        }
        dependencies.push(Dependency {
            package_id,
            version,
            source_package_digest: digest.to_string(),
        });
    }
    let ordered = dependencies.windows(2).all(|pair| {
        (&pair[0].package_id, &pair[0].version) < (&pair[1].package_id, &pair[1].version)
    });
    if !ordered {
        return Err(BuildError::shape(
            "package.json",
            path,
            "dependencies must be sorted strictly by (package_id, version)",
        ));
    }
    Ok(dependencies)
}

fn capability_declaration(value: &Json, path: String) -> Result<Vec<String>, BuildError> {
    let items = bind::array(value, path.clone()).map_err(manifest_shape)?;
    let mut capabilities = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let item_path = bind::pointer_index(&path, index);
        let name = bind::owned_string(item, item_path).map_err(manifest_shape)?;
        if !CAPABILITIES.contains(&name.as_str()) {
            return Err(BuildError::UnsupportedCapability { value: name });
        }
        capabilities.push(name);
    }
    if !crate::lexical::strictly_increasing(&capabilities) {
        return Err(BuildError::CapabilityLexical {
            value: format!("{capabilities:?}"),
        });
    }
    Ok(capabilities)
}

fn target_identity(value: &Json, path: String) -> Result<TargetIdentity, BuildError> {
    let object = Obj::new(path, "target_identity", value).map_err(manifest_shape)?;
    object.closed(TARGET_FIELDS).map_err(manifest_shape)?;
    let isa_family = field_string(&object, "isa_family")?;
    let isa_variant = field_string(&object, "isa_variant")?;
    let execution_mode = field_string(&object, "execution_mode")?;
    let byte_order = field_string(&object, "byte_order")?;
    let (address_width, address_path) = object.required("address_width").map_err(manifest_shape)?;
    let address_width =
        bind::bounded_u32(address_width, address_path, u32::MAX, "u32").map_err(manifest_shape)?;
    let (extensions, extensions_path) = object
        .required("enabled_extensions")
        .map_err(manifest_shape)?;
    let items = bind::array(extensions, extensions_path.clone()).map_err(manifest_shape)?;
    let mut enabled_extensions = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let item_path = bind::pointer_index(&extensions_path, index);
        enabled_extensions.push(bind::owned_string(item, item_path).map_err(manifest_shape)?);
    }
    if !crate::lexical::strictly_increasing(&enabled_extensions) {
        return Err(BuildError::ExtensionLexical {
            value: format!("{enabled_extensions:?}"),
        });
    }
    Ok(TargetIdentity {
        isa_family,
        isa_variant,
        execution_mode,
        enabled_extensions,
        byte_order,
        address_width,
    })
}

fn legacy_source(value: &Json, path: String) -> Result<LegacySource, BuildError> {
    let object = Obj::new(path, "legacy_source", value).map_err(manifest_shape)?;
    object.closed(LEGACY_FIELDS).map_err(manifest_shape)?;
    let isa = field_string(&object, "isa")?;
    let version = field_string(&object, "version")?;
    if !crate::lexical::legacy_isa(&isa) {
        return Err(BuildError::PathLexical {
            field: "legacy_source.isa",
            value: isa,
            reason: "a legacy component is lowercase letters, digits or `_`",
        });
    }
    if !crate::lexical::legacy_version(&version) {
        return Err(BuildError::PathLexical {
            field: "legacy_source.version",
            value: version,
            reason: "a legacy version is numeric components separated by `.`",
        });
    }
    Ok(LegacySource { isa, version })
}

fn field_string(object: &Obj<'_>, field: &'static str) -> Result<String, BuildError> {
    let (value, path) = object.required(field).map_err(manifest_shape)?;
    bind::owned_string(value, path).map_err(manifest_shape)
}

fn identifier(value: &Json, path: String, field: &'static str) -> Result<String, BuildError> {
    let value = bind::owned_string(value, path).map_err(manifest_shape)?;
    if let Err(reason) = crate::lexical::ident(&value) {
        return Err(BuildError::IdentifierLexical {
            field,
            value,
            reason,
        });
    }
    Ok(value)
}

fn version(value: &Json, path: String, field: &'static str) -> Result<String, BuildError> {
    let value = bind::owned_string(value, path).map_err(manifest_shape)?;
    if let Err(reason) = crate::lexical::version(&value) {
        return Err(BuildError::IdentifierLexical {
            field,
            value,
            reason,
        });
    }
    Ok(value)
}

fn declared_path(field: &'static str, value: &str) -> Result<(), BuildError> {
    if let Err(fault) = crate::lexical::path(value) {
        return Err(BuildError::PathLexical {
            field,
            value: value.to_string(),
            reason: fault.reason(),
        });
    }
    budget::check_path_length(field, value)
}

fn manifest_shape(fault: Fault) -> BuildError {
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
    BuildError::shape("package.json", fault.path(), reason)
}
