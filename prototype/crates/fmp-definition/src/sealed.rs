//! `bundles/sealed/<bundle_id>.bundle.json`: the self-contained bundle
//! (`ADR-0128` §8.2).
//!
//! The sealed bundle is the only artifact whose identity a reader can check
//! without the lock: the definition document and every field of the
//! `bundle_digest` preimage are inside the file. [`SealedBundle::verify`]
//! recomputes `definition_digest` from `definition`, `bundle_digest` from the
//! metadata the file carries, and requires both to equal the recorded values.
//!
//! The key set is exactly nine. `sources`, `path`, `builder` and
//! `release_digest` are unknown keys, not optional extras: a field that is not
//! in the preimage must not appear in the file and look like evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use fmp_model::bind::{self, Fault, Obj};
use fmp_model::canonical::canonical_bytes;
use fmp_model::definition;
use fmp_model::json::{self, Json};

use crate::budget::{self, Counter};
use crate::digest;
use crate::error::BuildError;
use crate::spec::{self, Target};

/// The only sealed-bundle format this builder interprets.
pub const BUNDLE_FORMAT: &str = "monasm-bundle/0.1";

const BUNDLE_FIELDS: &[&str] = &[
    "bundle_format",
    "bundle_id",
    "definition_format",
    "definition_digest",
    "bundle_digest",
    "target",
    "definition",
    "packages",
    "form_owners",
];
const PACKAGE_FIELDS: &[&str] = &[
    "package_id",
    "version",
    "source_package_digest",
    "enabled_extensions",
];
const OWNER_FIELDS: &[&str] = &["form_id", "package_id"];

/// One package row of the sealed `packages` array.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedPackage {
    pub package_id: String,
    pub version: String,
    pub source_package_digest: String,
    /// The owning package's declared cover, copied unchanged.
    pub enabled_extensions: Vec<String>,
}

/// One `{form_id, package_id}` ownership row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormOwner {
    pub form_id: String,
    pub package_id: String,
}

/// A parsed sealed bundle, before or after [`SealedBundle::verify`].
#[derive(Clone, Debug)]
pub struct SealedBundle {
    canonical: Json,
    bundle_id: String,
    definition_format: String,
    definition_digest: String,
    bundle_digest: String,
    target: Target,
    definition: Json,
    packages: Vec<SealedPackage>,
    form_owners: Vec<FormOwner>,
}

impl SealedBundle {
    /// Read and shape-check one sealed file.
    pub fn load(root: &Path, relative: &str) -> Result<SealedBundle, BuildError> {
        let mut counter = Counter::new("sealed bundle bytes", budget::SEALED_BYTES);
        let bytes = budget::read_regular(
            &root.join(relative),
            budget::SEALED_BYTES,
            "sealed bundle bytes",
            &mut counter,
        )?;
        let bundle = SealedBundle::parse(&bytes)?;
        crate::artifact::check_sealed(relative, &bundle.bundle_id)?;
        Ok(bundle)
    }

    /// Parse and shape-check the bytes; digests are checked by [`Self::verify`].
    pub fn parse(bytes: &[u8]) -> Result<SealedBundle, BuildError> {
        budget::check_depth(bytes)?;
        let value = json::parse(bytes)
            .map_err(|error| BuildError::shape("sealed bundle", "", error.reason()))?;
        SealedBundle::from_json(value)
    }

    pub fn from_json(value: Json) -> Result<SealedBundle, BuildError> {
        let root = Obj::new("", "sealed bundle", &value).map_err(bundle_shape)?;
        root.closed(BUNDLE_FIELDS).map_err(bundle_shape)?;

        let (bundle_format, path) = root.required("bundle_format").map_err(bundle_shape)?;
        let bundle_format = bind::string(bundle_format, path).map_err(bundle_shape)?;
        if bundle_format != BUNDLE_FORMAT {
            return Err(BuildError::shape(
                "sealed bundle",
                "/bundle_format",
                format!("{bundle_format:?} is not {BUNDLE_FORMAT}"),
            ));
        }

        let (bundle_id, path) = root.required("bundle_id").map_err(bundle_shape)?;
        let bundle_id = bind::owned_string(bundle_id, path).map_err(bundle_shape)?;
        if let Err(reason) = crate::lexical::ident(&bundle_id) {
            return Err(BuildError::IdentifierLexical {
                field: "bundle_id",
                value: bundle_id,
                reason,
            });
        }

        let (definition_format, path) = root.required("definition_format").map_err(bundle_shape)?;
        let definition_format = bind::string(definition_format, path).map_err(bundle_shape)?;
        if !crate::manifest::DEFINITION_FORMATS.contains(&definition_format) {
            return Err(BuildError::shape(
                "sealed bundle",
                "/definition_format",
                format!(
                    "{definition_format:?} is not one of {}",
                    crate::manifest::DEFINITION_FORMATS.join(", ")
                ),
            ));
        }

        let definition_digest = digest_field(&root, "definition_digest")?;
        let bundle_digest = digest_field(&root, "bundle_digest")?;

        let (target, path) = root.required("target").map_err(bundle_shape)?;
        let target = spec::parse_target(target, path, "sealed bundle")?;

        let (definition, path) = root.required("definition").map_err(bundle_shape)?;
        if !matches!(definition, Json::Object(_)) {
            return Err(BuildError::shape(
                "sealed bundle",
                path,
                "definition must be a JSON object",
            ));
        }

        let (packages, path) = root.required("packages").map_err(bundle_shape)?;
        let packages = package_rows(packages, path)?;
        let (owners, path) = root.required("form_owners").map_err(bundle_shape)?;
        let form_owners = owner_rows(owners, path)?;
        let definition = definition.clone();
        let definition_format = definition_format.to_string();

        Ok(SealedBundle {
            canonical: value,
            bundle_id,
            definition_format,
            definition_digest,
            bundle_digest,
            target,
            definition,
            packages,
            form_owners,
        })
    }

    pub fn canonical(&self) -> &Json {
        &self.canonical
    }

    pub fn bundle_id(&self) -> &str {
        &self.bundle_id
    }

    /// Recompute both digests from the file's own contents and compare them.
    ///
    /// This establishes the bundle's own identity. It does not establish which
    /// package paths, `evidence_digest` or `release_digest` produced it; those
    /// need the lock (§8.2).
    pub fn verify(&self) -> Result<(), BuildError> {
        let definition = self.read_definition()?;

        if definition.digest() != self.definition_digest {
            return Err(BuildError::DigestMismatch {
                field: "definition_digest",
                expected: self.definition_digest.clone(),
                actual: definition.digest().to_string(),
            });
        }
        if definition.definition_format() != self.definition_format {
            return Err(BuildError::DigestMismatch {
                field: "definition_format",
                expected: self.definition_format.clone(),
                actual: definition.definition_format().to_string(),
            });
        }
        compare_identity(&self.target, definition.target())?;

        let actual = digest::bundle_digest(&self.metadata_of(&definition));
        if actual != self.bundle_digest {
            return Err(BuildError::DigestMismatch {
                field: "bundle_digest",
                expected: self.bundle_digest.clone(),
                actual,
            });
        }

        self.check_owner_completeness(&definition)?;
        Ok(())
    }

    /// The exact `bundle_digest` preimage this file implies.
    ///
    /// A consumer that only holds the sealed bytes can recompute the digest from
    /// this value; a test can also change one field and recompute, which is how a
    /// rewritten ownership map is shown to be a different bundle identity rather
    /// than a same-digest edit.
    pub fn metadata(&self) -> Result<Json, BuildError> {
        let definition = self.read_definition()?;
        Ok(self.metadata_of(&definition))
    }

    fn metadata_of(&self, definition: &definition::Definition) -> Json {
        bundle_metadata(BundleMetadata {
            bundle_id: &self.bundle_id,
            definition_format: &self.definition_format,
            definition_digest: definition.digest(),
            namespace: definition.namespace(),
            version: definition.version(),
            target: &self.target.to_json(),
            packages: &self.packages,
            form_owners: &self.form_owners,
        })
    }

    pub fn packages(&self) -> &[SealedPackage] {
        &self.packages
    }

    pub fn form_owners(&self) -> &[FormOwner] {
        &self.form_owners
    }

    fn read_definition(&self) -> Result<definition::Definition, BuildError> {
        let bytes = canonical_bytes(&self.definition);
        definition::read(&bytes).map_err(|diagnostic| BuildError::DefinitionRejected {
            detail: diagnostic.message(),
        })
    }

    fn check_owner_completeness(
        &self,
        definition: &definition::Definition,
    ) -> Result<(), BuildError> {
        let packages: BTreeSet<&str> = self
            .packages
            .iter()
            .map(|package| package.package_id.as_str())
            .collect();
        let forms: BTreeMap<&str, ()> = definition
            .forms()
            .iter()
            .map(|form| (form.form_id.as_str(), ()))
            .collect();

        let mut seen = BTreeSet::new();
        for owner in &self.form_owners {
            if !packages.contains(owner.package_id.as_str()) {
                return Err(BuildError::BundleOwnerIncomplete {
                    subject: owner.form_id.clone(),
                    reason: "the owning package is not in packages",
                });
            }
            if !forms.contains_key(owner.form_id.as_str()) {
                return Err(BuildError::BundleOwnerIncomplete {
                    subject: owner.form_id.clone(),
                    reason: "the row names a form the definition does not carry",
                });
            }
            if !seen.insert(owner.form_id.clone()) {
                return Err(BuildError::BundleOwnerIncomplete {
                    subject: owner.form_id.clone(),
                    reason: "the form has more than one owner row",
                });
            }
        }
        for form_id in forms.keys() {
            if !seen.contains(*form_id) {
                return Err(BuildError::BundleOwnerIncomplete {
                    subject: (*form_id).to_string(),
                    reason: "the form has no owner row",
                });
            }
        }
        Ok(())
    }
}

/// The eight fields of the §8.2 `bundle_digest` preimage.
///
/// Named rather than positional: `namespace` and `version` are both strings, and
/// a swap at a positional call site would compile into a different digest.
pub struct BundleMetadata<'a> {
    pub bundle_id: &'a str,
    pub definition_format: &'a str,
    pub definition_digest: &'a str,
    pub namespace: &'a str,
    pub version: &'a str,
    pub target: &'a Json,
    pub packages: &'a [SealedPackage],
    pub form_owners: &'a [FormOwner],
}

/// The exact `bundle_digest` preimage of §8.2, in the order the canonicaliser
/// will sort.
pub fn bundle_metadata(parts: BundleMetadata<'_>) -> Json {
    let BundleMetadata {
        bundle_id,
        definition_format,
        definition_digest,
        namespace,
        version,
        target,
        packages,
        form_owners,
    } = parts;
    Json::Object(vec![
        ("bundle_id".to_string(), Json::Str(bundle_id.to_string())),
        (
            "definition_digest".to_string(),
            Json::Str(definition_digest.to_string()),
        ),
        (
            "definition_format".to_string(),
            Json::Str(definition_format.to_string()),
        ),
        ("form_owners".to_string(), owners_json(form_owners)),
        ("namespace".to_string(), Json::Str(namespace.to_string())),
        ("packages".to_string(), packages_json(packages)),
        ("target".to_string(), target.clone()),
        ("version".to_string(), Json::Str(version.to_string())),
    ])
}

/// The `packages` array of §8.2, in the order the canonicaliser will sort.
pub(crate) fn packages_json(packages: &[SealedPackage]) -> Json {
    Json::Array(
        packages
            .iter()
            .map(|package| {
                Json::Object(vec![
                    (
                        "enabled_extensions".to_string(),
                        Json::Array(
                            package
                                .enabled_extensions
                                .iter()
                                .map(|name| Json::Str(name.clone()))
                                .collect(),
                        ),
                    ),
                    (
                        "package_id".to_string(),
                        Json::Str(package.package_id.clone()),
                    ),
                    (
                        "source_package_digest".to_string(),
                        Json::Str(package.source_package_digest.clone()),
                    ),
                    ("version".to_string(), Json::Str(package.version.clone())),
                ])
            })
            .collect(),
    )
}

/// The `form_owners` array of §8.2, one row per merged form.
pub(crate) fn owners_json(form_owners: &[FormOwner]) -> Json {
    Json::Array(
        form_owners
            .iter()
            .map(|owner| {
                Json::Object(vec![
                    ("form_id".to_string(), Json::Str(owner.form_id.clone())),
                    (
                        "package_id".to_string(),
                        Json::Str(owner.package_id.clone()),
                    ),
                ])
            })
            .collect(),
    )
}

fn digest_field(object: &Obj<'_>, field: &'static str) -> Result<String, BuildError> {
    let (value, path) = object.required(field).map_err(bundle_shape)?;
    let value = bind::owned_string(value, path).map_err(bundle_shape)?;
    if !digest::is_sha256_literal(&value) {
        return Err(BuildError::shape(
            "sealed bundle",
            object.child(field),
            "expected the literal sha256:<64 lowercase hex>",
        ));
    }
    Ok(value)
}

fn package_rows(value: &Json, path: String) -> Result<Vec<SealedPackage>, BuildError> {
    let items = bind::array(value, path.clone()).map_err(bundle_shape)?;
    let mut packages = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let item_path = bind::pointer_index(&path, index);
        let object = Obj::new(item_path, "sealed package", item).map_err(bundle_shape)?;
        object.closed(PACKAGE_FIELDS).map_err(bundle_shape)?;
        let package_id = field_string(&object, "package_id")?;
        if let Err(reason) = crate::lexical::ident(&package_id) {
            return Err(BuildError::IdentifierLexical {
                field: "packages[].package_id",
                value: package_id,
                reason,
            });
        }
        let version = field_string(&object, "version")?;
        if let Err(reason) = crate::lexical::version(&version) {
            return Err(BuildError::IdentifierLexical {
                field: "packages[].version",
                value: version,
                reason,
            });
        }
        let source_package_digest = field_string(&object, "source_package_digest")?;
        if !digest::is_sha256_literal(&source_package_digest) {
            return Err(BuildError::shape(
                "sealed bundle",
                object.child("source_package_digest"),
                "expected the literal sha256:<64 lowercase hex>",
            ));
        }
        let (extensions, extensions_path) = object
            .required("enabled_extensions")
            .map_err(bundle_shape)?;
        let items = bind::array(extensions, extensions_path.clone()).map_err(bundle_shape)?;
        let mut enabled_extensions = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            enabled_extensions.push(
                bind::owned_string(item, bind::pointer_index(&extensions_path, index))
                    .map_err(bundle_shape)?,
            );
        }
        if !crate::lexical::strictly_increasing(&enabled_extensions) {
            return Err(BuildError::ExtensionLexical {
                value: format!("{enabled_extensions:?}"),
            });
        }
        packages.push(SealedPackage {
            package_id,
            version,
            source_package_digest,
            enabled_extensions,
        });
    }
    if !packages.windows(2).all(|pair| {
        (&pair[0].package_id, &pair[0].version) < (&pair[1].package_id, &pair[1].version)
    }) {
        return Err(BuildError::shape(
            "sealed bundle",
            path,
            "packages must be strictly sorted by (package_id, version)",
        ));
    }
    Ok(packages)
}

fn owner_rows(value: &Json, path: String) -> Result<Vec<FormOwner>, BuildError> {
    let items = bind::array(value, path.clone()).map_err(bundle_shape)?;
    let mut owners = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let item_path = bind::pointer_index(&path, index);
        let object = Obj::new(item_path, "form owner", item).map_err(bundle_shape)?;
        object.closed(OWNER_FIELDS).map_err(bundle_shape)?;
        let form_id = field_string(&object, "form_id")?;
        let package_id = field_string(&object, "package_id")?;
        owners.push(FormOwner {
            form_id,
            package_id,
        });
    }
    for pair in owners.windows(2) {
        if pair[0].form_id == pair[1].form_id {
            // §8.2 names a duplicate owner row `bundle-owner-incomplete`, so the
            // finding survives parsing as that class rather than as a shape
            // error: the array is sorted, it just names one form twice.
            return Err(BuildError::BundleOwnerIncomplete {
                subject: pair[0].form_id.clone(),
                reason: "the form has more than one owner row",
            });
        }
        if pair[0].form_id > pair[1].form_id {
            return Err(BuildError::shape(
                "sealed bundle",
                path,
                "form_owners must be strictly sorted by form_id",
            ));
        }
    }
    Ok(owners)
}

fn compare_identity(
    target: &Target,
    definition: &definition::DefinitionTarget,
) -> Result<(), BuildError> {
    let identity = &target.identity;
    for (field, equal) in [
        ("isa_family", identity.isa_family == definition.isa_family),
        (
            "isa_variant",
            identity.isa_variant == definition.isa_variant,
        ),
        (
            "execution_mode",
            identity.execution_mode == definition.execution_mode,
        ),
        ("byte_order", identity.byte_order == definition.byte_order),
        (
            "address_width",
            identity.address_width == definition.address_width,
        ),
        (
            "enabled_extensions",
            identity.enabled_extensions == definition.enabled_extensions,
        ),
    ] {
        if !equal {
            return Err(BuildError::TargetMismatch {
                package_id: "sealed bundle".to_string(),
                field,
            });
        }
    }
    Ok(())
}

fn field_string(object: &Obj<'_>, field: &'static str) -> Result<String, BuildError> {
    let (value, path) = object.required(field).map_err(bundle_shape)?;
    bind::owned_string(value, path).map_err(bundle_shape)
}

fn bundle_shape(fault: Fault) -> BuildError {
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
    BuildError::shape("sealed bundle", fault.path(), reason)
}
