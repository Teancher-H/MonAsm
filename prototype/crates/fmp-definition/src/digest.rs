//! The digest layers of `ADR-0128` §7, each with its own domain separator.
//!
//! Every digest here is SHA-256 over one exact byte string: the ASCII domain
//! separator, one `0x00`, then canonical JSON. A digest that appears as a JSON
//! string value is the literal text `sha256:` plus 64 lowercase hex characters
//! and is hashed **as that text** — never as 32 raw bytes, never uppercase.
//! That single rule is what makes the fixed vectors reproduce; an implementation
//! that feeds raw digest bytes into the outer hash fails them.
//!
//! The layers are separate on purpose: `definition_digest` names execution
//! rules, `source_package_digest` names a source snapshot, `evidence_digest`
//! names an audit trail and `release_digest` names the release. Folding one into
//! another makes a toolchain bump look like an encoding change, or an evidence
//! edit invisible (`HE-T19`).

use fmp_model::canonical::{canonical_bytes, canonical_digest, sha256_prefixed};
use fmp_model::json::Json;

/// `monasm-package/0.1` — `source_package_digest`.
pub const PACKAGE_DOMAIN: &[u8] = b"monasm-package/0.1";
/// `monasm-evidence/0.1` — `evidence_digest`.
pub const EVIDENCE_DOMAIN: &[u8] = b"monasm-evidence/0.1";
/// `monasm-bundle/0.1` — `bundle_digest`.
pub const BUNDLE_DOMAIN: &[u8] = b"monasm-bundle/0.1";
/// `monasm-release/0.1` — `release_digest`.
pub const RELEASE_DOMAIN: &[u8] = b"monasm-release/0.1";

/// The three asset kinds a manifest may declare.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetKind {
    Form,
    Type,
    Profile,
}

impl AssetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AssetKind::Form => "form",
            AssetKind::Type => "type",
            AssetKind::Profile => "profile",
        }
    }
}

/// One declared asset, as the source record names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asset {
    pub kind: AssetKind,
    /// Package-root-relative, already checked by §1.3.
    pub path: String,
    /// `sha256(canonical(asset))`, the literal text.
    pub digest: String,
}

/// `sha256(domain ++ 0x00 ++ canonical)`.
pub fn domain_digest(domain: &[u8], canonical: &[u8]) -> String {
    sha256_prefixed(&[domain, &[0u8], canonical])
}

/// The digest of one asset: `sha256(canonical(asset))`, no domain separator.
///
/// This is the value that goes into a source record. It is deliberately not
/// domain-separated: the record supplies the domain, and a per-asset separator
/// would make the record's own bytes unverifiable from the asset file alone.
pub fn asset_digest(value: &Json) -> String {
    canonical_digest(value)
}

/// The source record of §7.0: `{"manifest": <manifest>, "assets": [...]}` with
/// assets sorted by `path`.
///
/// The record is what `source_package_digest` hashes. It includes the manifest
/// exactly as declared — absent optional keys stay absent — so two manifests
/// that differ only in `"types": []` versus no `types` key are two snapshots.
pub fn source_record(manifest: &Json, assets: &[Asset]) -> Json {
    let mut sorted: Vec<&Asset> = assets.iter().collect();
    sorted.sort_by(|left, right| left.path.cmp(&right.path));
    let entries = sorted
        .iter()
        .map(|asset| {
            Json::Object(vec![
                ("digest".to_string(), Json::Str(asset.digest.clone())),
                (
                    "kind".to_string(),
                    Json::Str(asset.kind.as_str().to_string()),
                ),
                ("path".to_string(), Json::Str(asset.path.clone())),
            ])
        })
        .collect();
    Json::Object(vec![
        ("assets".to_string(), Json::Array(entries)),
        ("manifest".to_string(), manifest.clone()),
    ])
}

/// `source_package_digest` over the record.
pub fn source_package_digest(manifest: &Json, assets: &[Asset]) -> String {
    let record = source_record(manifest, assets);
    domain_digest(PACKAGE_DOMAIN, &canonical_bytes(&record))
}

/// `evidence_digest` over a parsed `evidence/manifest.json`.
pub fn evidence_digest(evidence_manifest: &Json) -> String {
    domain_digest(EVIDENCE_DOMAIN, &canonical_bytes(evidence_manifest))
}

/// `bundle_digest` over the bundle metadata of §8.2.
///
/// The metadata excludes the `bundle_digest` field itself: including a digest in
/// its own preimage has no fixed point. It includes `form_owners` and the
/// per-package cover, because H3 relies on those facts being content-addressed.
pub fn bundle_digest(metadata: &Json) -> String {
    domain_digest(BUNDLE_DOMAIN, &canonical_bytes(metadata))
}

/// `release_digest` over the release metadata of §8.2.
///
/// Every package entry of a committed lock carries `evidence_digest`; the
/// development shape omits it. The two shapes are different byte strings, so a
/// tool cannot write a development lock and later call it released.
pub fn release_digest(metadata: &Json) -> String {
    domain_digest(RELEASE_DOMAIN, &canonical_bytes(metadata))
}

/// Whether `value` is the literal `sha256:` plus 64 lowercase hex characters.
pub fn is_sha256_literal(value: &str) -> bool {
    match value.strip_prefix("sha256:") {
        Some(hex) => is_lower_hex(hex, 64),
        None => false,
    }
}

/// Whether `value` is 64 lowercase hex characters with no prefix.
///
/// The two bare-hash fields — `evidence/manifest.json` `files[].sha256` and a
/// case's `evidence.sha256` — use this form and hash raw committed bytes.
pub fn is_bare_sha256(value: &str) -> bool {
    is_lower_hex(value, 64)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
