//! Artifact file names carry the bundle identity (`ADR-0128` §8, §8.2).
//!
//! A spec, lock, sealed bundle and legacy snapshot are four different files for
//! one `bundle_id`. If a file's name could drift from the identity inside it, a
//! directory listing would decide which release a consumer reads (`INV-05`), so
//! every writer and reader checks the name before trusting the content.

use std::path::Path;

use crate::error::BuildError;

/// `bundles/specs/<bundle_id>.json`.
pub fn check_spec(relative: &str, bundle_id: &str) -> Result<(), BuildError> {
    expect(relative, "spec", &format!("{bundle_id}.json"))
}

/// `bundles/locks/<bundle_id>.lock.json`.
pub fn check_lock(relative: &str, bundle_id: &str) -> Result<(), BuildError> {
    expect(relative, "lock", &format!("{bundle_id}.lock.json"))
}

/// `bundles/sealed/<bundle_id>.bundle.json`.
pub fn check_sealed(relative: &str, bundle_id: &str) -> Result<(), BuildError> {
    expect(relative, "sealed", &format!("{bundle_id}.bundle.json"))
}

/// `bundles/legacy/<bundle_id>/definition.json`: the directory names the bundle.
pub fn check_legacy(relative: &str, bundle_id: &str) -> Result<(), BuildError> {
    let path = Path::new(relative);
    if path.file_name().and_then(|name| name.to_str()) != Some("definition.json") {
        return Err(BuildError::BundleFileMismatch {
            artifact: "legacy",
            expected: "definition.json".to_string(),
            actual: path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(relative)
                .to_string(),
        });
    }
    let actual = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if actual != bundle_id {
        return Err(BuildError::BundleFileMismatch {
            artifact: "legacy",
            expected: bundle_id.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(())
}

fn expect(relative: &str, artifact: &'static str, expected: &str) -> Result<(), BuildError> {
    let actual = Path::new(relative)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if actual == expected {
        Ok(())
    } else {
        Err(BuildError::BundleFileMismatch {
            artifact,
            expected: expected.to_string(),
            actual: actual.to_string(),
        })
    }
}
