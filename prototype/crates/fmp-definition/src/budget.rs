//! The explicit bounds of `ADR-0128` §12, and the reader that enforces them.
//!
//! Two properties matter more than the constants:
//!
//! - **The bound is charged against bytes actually read.** File metadata is a
//!   hint that lets the builder fail early; a file can grow between the hint and
//!   the read, so the reader stops at the remaining budget and treats an overrun
//!   as [`BuildError::ResourceLimit`]. Per-file limits alone would pass 2048
//!   files of 1 MiB each (§12.1).
//! - **The depth budget is enforced before parsing.** `fmp_model::json::parse`
//!   descends recursively, so a small document with tens of thousands of `[`
//!   would exhaust the stack instead of being rejected. The scan below is
//!   iterative and runs on the raw bytes, before the parser is called (§12).
//!
//! The type check is made on the opened handle, not on a path `stat`: a FIFO has
//! no bounded length, so a size check cannot bound a read from it (§3). What the
//! reader does **not** do is refuse a link on the path — portable `std::fs` has
//! no no-follow open, and that guarantee is the publication channel's, not this
//! node's.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::error::BuildError;

/// `package.json`.
pub const MANIFEST_BYTES: u64 = 1 << 20;
/// One form, type or profile file.
pub const ASSET_BYTES: u64 = 1 << 20;
/// `tests/cases.json`.
pub const CASES_BYTES: u64 = 16 << 20;
/// `evidence/manifest.json`.
pub const EVIDENCE_MANIFEST_BYTES: u64 = 1 << 20;
/// A spec or a lock.
pub const ARTIFACT_BYTES: u64 = 1 << 20;
/// A committed sealed bundle: the 64 MiB closure budget plus a 16 MiB envelope.
pub const SEALED_BYTES: u64 = 80 << 20;
/// The pinned legacy definition read for row comparison.
pub const LEGACY_DEFINITION_BYTES: u64 = 16 << 20;
/// Manifest plus declared asset bytes, per package.
pub const PACKAGE_BYTES: u64 = 16 << 20;
/// Exported forms per package.
pub const FORMS_PER_PACKAGE: u64 = 1024;
/// Declared assets per package.
pub const ASSETS_PER_PACKAGE: u64 = 2048;
/// Cases per package.
pub const CASES_PER_PACKAGE: u64 = 4096;
/// Evidence files per package.
pub const EVIDENCE_FILES: u64 = 4096;
/// Total evidence bytes per package, excluding `tests/cases.json`.
pub const EVIDENCE_BYTES: u64 = 16 << 20;
/// Total package-root bytes read for one closure (§12.2).
pub const CLOSURE_BYTES: u64 = 64 << 20;
/// Packages per closure.
pub const PACKAGES_PER_CLOSURE: u64 = 1024;
/// Total declared assets per closure.
pub const ASSETS_PER_CLOSURE: u64 = 65_536;
/// Total evidence files per closure.
pub const EVIDENCE_FILES_PER_CLOSURE: u64 = 65_536;
/// One path, in bytes.
pub const PATH_BYTES: u64 = 1024;
/// JSON nesting depth, for every document the builder parses.
pub const JSON_DEPTH: u64 = 64;
/// Dependency depth.
pub const DEPENDENCY_DEPTH: u64 = 64;

/// One cumulative byte counter. §12 has two of them — manifest plus declared
/// assets per package, and total evidence bytes per package — and they are not
/// interchangeable: a case file must not be able to spend the asset budget, and
/// an asset must not be able to spend the evidence one.
///
/// `tests/cases.json` has its own per-file bound (`CASES_BYTES`) and is **not**
/// charged to the evidence counter. §12.2's counterexample requires one package
/// to carry 12 MiB of cases plus 12 MiB of evidence and still stay inside every
/// per-package limit; counting cases as evidence would make that legal
/// composition impossible. The closure counter below charges both, which is the
/// budget that bounds the run.
#[derive(Clone, Debug)]
pub struct Counter {
    budget: &'static str,
    limit: u64,
    spent: u64,
}

impl Counter {
    pub fn new(budget: &'static str, limit: u64) -> Self {
        Counter {
            budget,
            limit,
            spent: 0,
        }
    }

    /// The §12.1 counter: manifest plus declared asset bytes.
    pub fn package() -> Self {
        Counter::new(
            "manifest and declared asset bytes per package",
            PACKAGE_BYTES,
        )
    }

    /// The §12 evidence counter: every evidence file except `tests/cases.json`.
    pub fn evidence() -> Self {
        Counter::new("total evidence bytes per package", EVIDENCE_BYTES)
    }

    /// The case-file counter. One package has one case file, bounded by
    /// [`CASES_BYTES`]; the counter exists so a second open cannot evade it.
    pub fn cases() -> Self {
        Counter::new("case file bytes per package", CASES_BYTES)
    }

    pub fn spent(&self) -> u64 {
        self.spent
    }

    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.spent)
    }

    /// Charge `amount` bytes, rejecting the read that would cross the limit.
    pub fn charge(&mut self, amount: u64) -> Result<(), BuildError> {
        let next = self.spent.saturating_add(amount);
        if next > self.limit {
            return Err(BuildError::ResourceLimit {
                budget: self.budget,
                limit: self.limit,
            });
        }
        self.spent = next;
        Ok(())
    }
}

/// The §12.2 closure counter: one per run, 64 MiB, charged **once** per distinct
/// `(package root, path)`.
///
/// A command that opens the same file twice — for example a form asset that the
/// evidence manifest also lists — pays for it once. The counted set is keyed by
/// the declared package root as well as the file path, because the closure's
/// conflict domain is repository-root-relative; two packages may legally hold
/// the same package-root-relative path.
#[derive(Clone, Debug)]
pub struct ClosureCounter {
    limit: u64,
    spent: u64,
    charged: BTreeSet<(String, String)>,
}

impl ClosureCounter {
    pub fn new() -> Self {
        ClosureCounter {
            limit: CLOSURE_BYTES,
            spent: 0,
            charged: BTreeSet::new(),
        }
    }

    pub fn spent(&self) -> u64 {
        self.spent
    }

    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.spent)
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Whether this root/path pair has already been charged in this run.
    pub fn charged(&self, root: &str, path: &str) -> bool {
        self.charged.contains(&(root.to_string(), path.to_string()))
    }

    /// Charge the raw byte length of one read, once per path.
    ///
    /// The crossing read is rejected before its bytes are added: `spent` is left
    /// unchanged and the path is not marked as counted.
    pub fn charge(&mut self, root: &str, path: &str, amount: u64) -> Result<(), BuildError> {
        let key = (root.to_string(), path.to_string());
        if self.charged.contains(&key) {
            return Ok(());
        }
        let next = self.spent.saturating_add(amount);
        if next > self.limit {
            return Err(BuildError::AggregateLimit { limit: self.limit });
        }
        self.spent = next;
        self.charged.insert(key);
        Ok(())
    }
}

impl Default for ClosureCounter {
    fn default() -> Self {
        ClosureCounter::new()
    }
}

/// Open a leaf, check that the opened object is a regular file, and read it
/// under both its own limit and the cumulative counter.
///
/// `limit_name` names the per-file bound in the rejection, so a reader can tell a
/// 1 MiB asset limit from the 16 MiB cumulative one.
pub fn read_regular(
    path: &Path,
    per_file: u64,
    limit_name: &'static str,
    counter: &mut Counter,
) -> Result<Vec<u8>, BuildError> {
    let display = path.display().to_string();
    let file = File::open(path).map_err(|error| BuildError::io(&display, error))?;
    read_open(file, display, per_file, limit_name, counter, None)
}

/// [`read_regular`], also charged against the one closure counter.
///
/// `root` is the declared package root and `relative` the package-root-relative
/// path; together they form the counted key.
pub fn read_regular_tracked(
    path: &Path,
    per_file: u64,
    limit_name: &'static str,
    counter: &mut Counter,
    closure: &mut ClosureCounter,
    root: &str,
    relative: &str,
) -> Result<Vec<u8>, BuildError> {
    let display = path.display().to_string();
    let file = File::open(path).map_err(|error| BuildError::io(&display, error))?;
    read_open(
        file,
        display,
        per_file,
        limit_name,
        counter,
        Some((closure, root, relative)),
    )
}

/// Read a file that is allowed to be absent.
///
/// Only a real `NotFound` becomes `None`: a permission error or a directory
/// where a file is expected stays an error, so "optional" cannot hide a host
/// failure. The read uses the handle from the single open, not a second open of
/// the same path.
pub fn read_optional(
    path: &Path,
    per_file: u64,
    limit_name: &'static str,
    counter: &mut Counter,
) -> Result<Option<Vec<u8>>, BuildError> {
    read_optional_inner(path, per_file, limit_name, counter, None)
}

/// [`read_optional`], also charged against the closure counter.
pub fn read_optional_tracked(
    path: &Path,
    per_file: u64,
    limit_name: &'static str,
    counter: &mut Counter,
    closure: &mut ClosureCounter,
    root: &str,
    relative: &str,
) -> Result<Option<Vec<u8>>, BuildError> {
    read_optional_inner(
        path,
        per_file,
        limit_name,
        counter,
        Some((closure, root, relative)),
    )
}

type Tracking<'a> = Option<(&'a mut ClosureCounter, &'a str, &'a str)>;

fn read_optional_inner(
    path: &Path,
    per_file: u64,
    limit_name: &'static str,
    counter: &mut Counter,
    tracking: Tracking<'_>,
) -> Result<Option<Vec<u8>>, BuildError> {
    let display = path.display().to_string();
    match File::open(path) {
        Ok(file) => read_open(file, display, per_file, limit_name, counter, tracking).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(BuildError::io(&display, error)),
    }
}

fn read_open(
    mut file: File,
    display: String,
    per_file: u64,
    limit_name: &'static str,
    counter: &mut Counter,
    tracking: Tracking<'_>,
) -> Result<Vec<u8>, BuildError> {
    let metadata = file
        .metadata()
        .map_err(|error| BuildError::io(&display, error))?;
    if !metadata.is_file() {
        return Err(BuildError::NotARegularFile { path: display });
    }
    let allowance = per_file.min(counter.remaining());
    if metadata.len() > allowance {
        return Err(BuildError::ResourceLimit {
            budget: limit_name,
            limit: allowance,
        });
    }
    // §12.2 rejects at the read that would cross the closure limit. The metadata
    // hint is enough to stop before the crossing bytes; the post-read charge
    // catches a file that grew between the hint and the read.
    if let Some((closure, root, relative)) = tracking.as_ref() {
        if !closure.charged(root, relative) && metadata.len() > closure.remaining() {
            return Err(BuildError::AggregateLimit {
                limit: closure.limit(),
            });
        }
    }
    // One byte past the allowance is enough to detect a file that grew after the
    // hint without reading an unbounded stream.
    let mut bytes = Vec::new();
    let read = file
        .by_ref()
        .take(allowance.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| BuildError::io(&display, error))?;
    if read as u64 > allowance {
        return Err(BuildError::ResourceLimit {
            budget: limit_name,
            limit: allowance,
        });
    }
    counter.charge(read as u64)?;
    if let Some((closure, root, relative)) = tracking {
        closure.charge(root, relative, read as u64)?;
    }
    Ok(bytes)
}

/// Reject a document that nests deeper than [`JSON_DEPTH`] without recursing.
///
/// The scan counts `{` and `[` outside string literals, honouring `\"` inside a
/// string. It is deliberately indifferent to whether the document is otherwise
/// well formed: its job is to bound the parser's descent, and the parser still
/// owns every grammar rule.
pub fn check_depth(bytes: &[u8]) -> Result<(), BuildError> {
    let mut depth: u64 = 0;
    let mut in_string = false;
    let mut escaped = false;
    for byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > JSON_DEPTH {
                    return Err(BuildError::ResourceLimit {
                        budget: "JSON nesting depth",
                        limit: JSON_DEPTH,
                    });
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

/// Reject a declared path longer than [`PATH_BYTES`].
///
/// The length is a budget, not a grammar rule: the path is otherwise legal, it
/// is simply larger than the format bounds (`ADR-0128` §12).
pub fn check_path_length(field: &'static str, value: &str) -> Result<(), BuildError> {
    if value.len() as u64 > PATH_BYTES {
        return Err(BuildError::ResourceLimit {
            budget: field,
            limit: PATH_BYTES,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_closure_path_is_charged_once_and_the_crossing_read_is_refused() {
        let mut closure = ClosureCounter::new();
        closure.charge("packages/x/a/0.1.0", "NOTICE", 10).unwrap();
        closure.charge("packages/x/a/0.1.0", "NOTICE", 10).unwrap();
        assert_eq!(closure.spent(), 10, "a path is paid for once per root");

        // The same package-relative path under another root is another file.
        closure.charge("packages/x/b/0.1.0", "NOTICE", 10).unwrap();
        assert_eq!(closure.spent(), 20);

        let mut small = ClosureCounter::new();
        small.charge("root", "a", CLOSURE_BYTES).unwrap();
        let error = small
            .charge("root", "b", 1)
            .expect_err("the next byte crosses the limit");
        assert_eq!(error.code(), "aggregate-limit");
        assert_eq!(small.spent(), CLOSURE_BYTES);
        assert!(!small.charged("root", "b"), "a refused read is not counted");
    }
}
