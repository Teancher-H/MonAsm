//! `CheckedBundle`: the value a build or a `--check` comparison produces
//! (`ADR-0128` §8, §8.2, §10).
//!
//! The name is the contract. A `CheckedBundle` means the selected closure was
//! read once, closed, path-checked, read again under each package's own target,
//! ownership-checked, merged, and serialised into a lock/sealed pair whose
//! recorded digests match the bytes produced from those inputs. It does **not**
//! mean the bundle is published, registered, or that V-P passed: those are
//! properties of a tree and the registry, reported by `verify --published
//! --check`, and no value of this type carries them.

use std::path::Path;
use std::sync::Arc;

use fmp_model::canonical::canonical_bytes;
use fmp_model::definition::Definition;
use fmp_model::json::Json;

use crate::budget;
use crate::closure::Closure;
use crate::error::BuildError;
use crate::lock::LOCK_FORMAT;
use crate::sealed::BUNDLE_FORMAT;
use crate::spec::Spec;

/// Who produced a lock. `build` is omitted when absent, never written as `null`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Builder {
    pub name: String,
    pub version: String,
    pub build: Option<String>,
}

impl Builder {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Builder {
        Builder {
            name: name.into(),
            version: version.into(),
            build: None,
        }
    }

    pub fn with_build(mut self, build: impl Into<String>) -> Builder {
        self.build = Some(build.into());
        self
    }
}

impl Default for Builder {
    fn default() -> Self {
        Builder::new("fmp-definition", env!("CARGO_PKG_VERSION"))
    }
}

/// A checked closure plus the two artifacts generated from it.
#[derive(Debug)]
pub struct CheckedBundle {
    closure: Closure,
    lock: Json,
    sealed: Json,
}

impl CheckedBundle {
    /// Build and self-check one bundle.
    ///
    /// The sealed document is serialised, parsed again and verified before the
    /// value is returned, so a bundle that does not verify its own digests is
    /// never handed out as checked.
    pub fn build(root: &Path, spec: &Spec, builder: Builder) -> Result<CheckedBundle, BuildError> {
        let closure = Closure::build(root, spec)?;
        let lock = lock_document(&closure, &builder);
        let sealed = sealed_document(&closure);

        let sealed_bytes = canonical_bytes(&sealed);
        if sealed_bytes.len() as u64 > budget::SEALED_BYTES {
            return Err(BuildError::ResourceLimit {
                budget: "sealed bundle bytes",
                limit: budget::SEALED_BYTES,
            });
        }
        // The sealed bundle is the artifact a consumer may hold alone, so the
        // build proves its self-verification before returning.
        crate::sealed::SealedBundle::from_json(sealed.clone())?.verify()?;

        Ok(CheckedBundle {
            closure,
            lock,
            sealed,
        })
    }

    pub fn definition_digest(&self) -> &str {
        self.closure.definition_digest()
    }

    pub fn bundle_digest(&self) -> &str {
        self.closure.bundle_digest()
    }

    pub fn lock_json(&self) -> Json {
        self.lock.clone()
    }

    pub fn bundle_json(&self) -> Json {
        self.sealed.clone()
    }

    pub fn release_digest(&self) -> &str {
        self.closure.release_digest()
    }

    pub fn closure(&self) -> &Closure {
        &self.closure
    }

    pub(crate) fn definition_arc(&self) -> Arc<Definition> {
        self.closure.definition_arc()
    }
}

/// The `monasm-lock/0.1` document of §8.2.
pub fn lock_document(closure: &Closure, builder: &Builder) -> Json {
    let spec = closure.spec();
    let packages = closure
        .packages()
        .iter()
        .map(|package| {
            Json::Object(vec![
                // `Closure::build` refuses a package without release evidence, so a
                // lock never exists for a development-shaped entry (§7.1). An empty
                // string here would be an invalid digest written as a repair.
                (
                    "evidence_digest".to_string(),
                    Json::Str(
                        package
                            .evidence_digest()
                            .expect("a locked package is release-ready")
                            .to_string(),
                    ),
                ),
                (
                    "package_id".to_string(),
                    Json::Str(package.manifest().package_id().to_string()),
                ),
                (
                    "path".to_string(),
                    Json::Str(package.relative().to_string()),
                ),
                (
                    "source_package_digest".to_string(),
                    Json::Str(package.source_package_digest().to_string()),
                ),
                (
                    "version".to_string(),
                    Json::Str(package.manifest().version().to_string()),
                ),
            ])
        })
        .collect();
    let mut builder_fields = vec![
        ("name".to_string(), Json::Str(builder.name.clone())),
        ("version".to_string(), Json::Str(builder.version.clone())),
    ];
    if let Some(build) = &builder.build {
        builder_fields.push(("build".to_string(), Json::Str(build.clone())));
    }
    Json::Object(vec![
        ("builder".to_string(), Json::Object(builder_fields)),
        (
            "bundle_digest".to_string(),
            Json::Str(closure.bundle_digest().to_string()),
        ),
        (
            "bundle_id".to_string(),
            Json::Str(spec.bundle_id().to_string()),
        ),
        (
            "definition_digest".to_string(),
            Json::Str(closure.definition_digest().to_string()),
        ),
        (
            "definition_format".to_string(),
            Json::Str(spec.definition_format().to_string()),
        ),
        (
            "lock_format".to_string(),
            Json::Str(LOCK_FORMAT.to_string()),
        ),
        (
            "namespace".to_string(),
            Json::Str(spec.namespace().to_string()),
        ),
        ("packages".to_string(), Json::Array(packages)),
        (
            "release_digest".to_string(),
            Json::Str(closure.release_digest().to_string()),
        ),
        ("target".to_string(), spec.target().to_json()),
        ("version".to_string(), Json::Str(spec.version().to_string())),
    ])
}

/// The `monasm-bundle/0.1` document of §8.2: exactly nine keys.
pub fn sealed_document(closure: &Closure) -> Json {
    let spec = closure.spec();
    Json::Object(vec![
        (
            "bundle_digest".to_string(),
            Json::Str(closure.bundle_digest().to_string()),
        ),
        (
            "bundle_format".to_string(),
            Json::Str(BUNDLE_FORMAT.to_string()),
        ),
        (
            "bundle_id".to_string(),
            Json::Str(spec.bundle_id().to_string()),
        ),
        ("definition".to_string(), closure.definition_value().clone()),
        (
            "definition_digest".to_string(),
            Json::Str(closure.definition_digest().to_string()),
        ),
        (
            "definition_format".to_string(),
            Json::Str(spec.definition_format().to_string()),
        ),
        (
            "form_owners".to_string(),
            crate::sealed::owners_json(closure.form_owners()),
        ),
        (
            "packages".to_string(),
            crate::sealed::packages_json(closure.sealed_packages()),
        ),
        ("target".to_string(), spec.target().to_json()),
    ])
}
