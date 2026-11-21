//! The target-package author layer: read a package, check it, and name it.
//!
//! The contract is `docs/adr/0128-package-and-bundle-contract.md` (referred to
//! below as "the ADR"). This crate is the development-time builder; it is never
//! a dependency of the validator or the materializer, and the only typed bridge
//! into `fmp/model` is the compat function of ADR §10.
//!
//! ## What this layer is
//!
//! H2a is the *author layer*: one package directory, read once, checked against
//! its own declaration, and given its own digests. It makes no publication claim
//! — no lock, sealed bundle, registry or merge-authority fact is established by
//! anything here, and the ADR's second verdict (the publication channel) is not
//! implied by this crate passing its tests.
//!
//! ## The one loaded package
//!
//! A package is opened once. The bytes that are hashed are the bytes that are
//! parsed and later merged, so a file change between two opens cannot make the
//! digest name one buffer and the definition contain another (ADR §9). This is
//! the `LoadedPackage` invariant, and it is why the loader returns owned bytes
//! instead of re-reading paths on demand.
//!
//! ## What the trusted-tree reader does not claim
//!
//! The reader below opens ordinary paths. It checks the file type on the opened
//! handle and charges every byte it reads against a budget, but it follows a
//! link or reparse point if one is present, because portable `std::fs` has no
//! no-follow open (ADR §3). The hardened reader is the publication channel's
//! deliverable and is gated on the three-platform PoC; until that lands, a
//! successful load here is evidence about the *content* of a package, not about
//! the absence of a link on the path used to reach it.
//!
//! ## Error vocabulary
//!
//! The builder has its own `BuildError`; it does not add `E-*` codes and does
//! not pretend to be an `fmp/0.1` diagnostic (ADR §11). The ADR's variant list is
//! introduced with "the enum names these rejections" over a list that covers
//! every *named* rejection; two rejection classes the ADR requires in prose but
//! does not name are spelled here as:
//!
//! - `document-shape` — a builder-parsed document broke its closed shape
//!   (unknown, missing or duplicated key, wrong JSON type, or a `*_format`
//!   string this version does not interpret). ADR §1, §7.0 and §8.2 require the
//!   rejection; §11 lists it only as "manifest shape (required/optional keys)".
//! - `definition-rejected` — `fmp_model::definition::read` refused the document
//!   the builder generated, re-raised with the underlying text preserved
//!   (ADR §9). Used from the merge onward, not in this node.
//!
//! Both are additions to the vocabulary, not to the semantics: nothing that the
//! ADR accepts becomes rejected, and nothing it rejects becomes accepted.

#![forbid(unsafe_code)]

pub mod budget;
pub mod digest;
pub mod error;
pub mod evidence;
pub mod lexical;
pub mod manifest;
pub mod package;

pub use error::BuildError;
pub use manifest::Manifest;
pub use package::LoadedPackage;
