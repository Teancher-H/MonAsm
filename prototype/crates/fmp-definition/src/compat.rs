//! The one narrowing from a checked bundle to the H1 entry (`ADR-0128` §10).
//!
//! The adapter is a free function in its own module on purpose: every call site
//! reads `compat::`, a glob import cannot reach it by accident, and no method on
//! [`CheckedBundle`] presents the narrowed value as part of the bundle's own
//! surface. Its guarantee is scoped to this entry: it keeps the executed value
//! equal to the digested value, not that every possible path to an
//! `Arc<Definition>` went through a bundle.
//!
//! There is no reverse conversion, no public constructor and no `definition()`
//! accessor:
//!
//! ```compile_fail
//! # use fmp_definition::build::CheckedBundle;
//! fn widen(bundle: &CheckedBundle) {
//!     let _ = bundle.definition();
//! }
//! ```
//!
//! The bypass through `bundle_json()` and `fmp_model::definition::read` is legal
//! and compiles, but it loses the bundle's identity, ownership cover and digest
//! binding, so no report may cite the resulting `Definition` as bundle evidence.
//! The adapter's value is that the executed value is the digested value.

use std::sync::Arc;

use fmp_model::definition::Definition;

use crate::build::CheckedBundle;

/// Narrow a checked bundle to the H1 `Arc<Definition>` that `bind` consumes.
///
/// The returned value is the very `Definition` the merge produced and the sealed
/// bundle records; it is never re-read from the sealed bytes.
pub fn as_legacy_definition(bundle: &CheckedBundle) -> Arc<Definition> {
    bundle.definition_arc()
}
