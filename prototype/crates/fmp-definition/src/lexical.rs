//! The four grammars of `ADR-0128` §1.3, and the fold rule that belongs with
//! them.
//!
//! The rules exist so that one document has one meaning on ext4, APFS and NTFS.
//! They are therefore checked on the **string**, before any file is opened, and
//! they are pure ASCII: a non-ASCII character is a portability rejection, not a
//! value whose case folding depends on the host's Unicode tables. That keeps
//! "the same package" independent of the locale the builder happens to run in
//! (`INV-05`).
//!
//! ```text
//! ident    = ^[a-z][a-z0-9]*(\.[a-z][a-z0-9_-]*)+$
//! version  = ^(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){2,}(-[a-z0-9]+([.-][a-z0-9]+)*)?$
//! pseg     = ^[a-z0-9_][a-z0-9_.-]*$
//! path     = pseg ("/" pseg)*
//! ```

/// The only uppercase spellings §1.3 admits, and only as whole segments.
pub const FIXED_UPPERCASE: [&str; 2] = ["README.md", "NOTICE"];

/// Why a declared path is not portable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathFault {
    Empty,
    /// A leading `/`, a drive letter or a URL scheme: the path is not relative.
    Absolute,
    Backslash,
    Control,
    EmptySegment,
    /// `.`, `..`, or a segment that merely contains `..`.
    ParentSegment,
    NotPortableSegment,
    DeviceName,
    TrailingDotOrSpace,
}

impl PathFault {
    /// The reason a diagnostic prints. Each one names the repair the format
    /// refuses to perform.
    pub fn reason(self) -> &'static str {
        match self {
            PathFault::Empty => "the path is empty",
            PathFault::Absolute => "the path is not relative to its root",
            PathFault::Backslash => "a path separator is `/`, never `\\`",
            PathFault::Control => "the path contains a control character",
            PathFault::EmptySegment => "the path has an empty segment",
            PathFault::ParentSegment => "the path contains `.` or `..`",
            PathFault::NotPortableSegment => "a segment must match pseg or be README.md/NOTICE",
            PathFault::DeviceName => "a segment is a Windows device name",
            PathFault::TrailingDotOrSpace => "a segment ends with `.` or a space",
        }
    }
}

/// `ident`: a dotted identifier with at least two segments.
///
/// `package_id`, `bundle_id`, `namespace`, `target_profile` and `profile_id` use
/// this grammar. The first segment may not contain `-` or `_`; later segments
/// may. `monasm.x86.mov-register` is legal, `Monasm.X86.Mov`, `monasm..x86`,
/// `monasm.x86.` and `..x86` are not.
pub fn ident(value: &str) -> Result<(), &'static str> {
    let mut segments = value.split('.');
    let first = segments.next().unwrap_or("");
    if first.is_empty() {
        return Err("an identifier is not empty");
    }
    if !starts_lowercase(first) {
        return Err("an identifier segment starts with a lowercase letter");
    }
    if !first
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err("the first identifier segment is lowercase letters and digits");
    }
    let mut count = 1;
    for segment in segments {
        count += 1;
        if segment.is_empty() {
            return Err("an identifier has no empty segment");
        }
        if !starts_lowercase(segment) {
            return Err("an identifier segment starts with a lowercase letter");
        }
        if !segment.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        }) {
            return Err("an identifier segment is lowercase letters, digits, `-` or `_`");
        }
    }
    if count < 2 {
        return Err("an identifier has at least two segments");
    }
    Ok(())
}

/// `version`: at least three numeric components, no leading zero, then an
/// optional lowercase pre-release.
///
/// `0.1.0`, `0.2.0` and `0.1.0-h2` are legal; `0.1`, `01.0`, `0.1.0-H2` and
/// `0.1.0-` are not. The derived standalone version of §2.1 is outside this
/// grammar and never appears in a manifest, spec, lock or path.
pub fn version(value: &str) -> Result<(), &'static str> {
    let (core, pre) = match value.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (value, None),
    };
    let mut components = core.split('.');
    let mut count = 0;
    for component in components.by_ref() {
        count += 1;
        if component.is_empty() {
            return Err("a version component is not empty");
        }
        if !numeric_component(component) {
            return Err("a version component is `0` or digits without a leading zero");
        }
    }
    if count < 3 {
        return Err("a version has at least three numeric components");
    }
    if let Some(pre) = pre {
        if pre.is_empty() {
            return Err("a pre-release has at least one character");
        }
        let mut expecting_word = true;
        for character in pre.chars() {
            if character == '.' || character == '-' {
                if expecting_word {
                    return Err("a pre-release separator is not leading, doubled or trailing");
                }
                expecting_word = true;
            } else if character.is_ascii_lowercase() || character.is_ascii_digit() {
                expecting_word = false;
            } else {
                return Err("a pre-release is lowercase letters and digits");
            }
        }
        if expecting_word {
            return Err("a pre-release separator is not leading, doubled or trailing");
        }
    }
    Ok(())
}

/// `path`: relative, `/`-separated, every segment portable.
///
/// The two fixed uppercase names are whole-segment exemptions; they are never an
/// asset path. A segment that is a Windows device name is rejected with or
/// without an extension, because `forms/NUL.json` opens a device on Windows and
/// is an ordinary file elsewhere.
pub fn path(value: &str) -> Result<(), PathFault> {
    if value.is_empty() {
        return Err(PathFault::Empty);
    }
    if value.starts_with('/') {
        return Err(PathFault::Absolute);
    }
    for character in value.chars() {
        if character == '\\' {
            return Err(PathFault::Backslash);
        }
        if character.is_control() {
            return Err(PathFault::Control);
        }
    }
    if value.contains(':') {
        // A drive letter or a URL scheme; `:` is outside pseg either way, but
        // naming it here makes the diagnostic about the shape, not a character.
        return Err(PathFault::Absolute);
    }
    for segment in value.split('/') {
        if segment.is_empty() {
            return Err(PathFault::EmptySegment);
        }
        if segment == "." || segment == ".." || segment.contains("..") {
            return Err(PathFault::ParentSegment);
        }
        if FIXED_UPPERCASE.contains(&segment) {
            continue;
        }
        if segment.ends_with('.') || segment.ends_with(' ') {
            return Err(PathFault::TrailingDotOrSpace);
        }
        if !portable_segment(segment) {
            return Err(PathFault::NotPortableSegment);
        }
        if is_device_name(segment) {
            return Err(PathFault::DeviceName);
        }
    }
    Ok(())
}

/// `legacy_source.isa`: one component of `<root>/definitions/<isa>/<version>.json`.
///
/// Narrower than `pseg` on purpose: the value is concatenated into a path, so it
/// may not carry a dot, a dash or anything that a host might read as structure.
pub fn legacy_isa(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// `legacy_source.version`: numeric components only, no pre-release.
///
/// The legacy corpus is the frozen definition corpus of `fmp/0.1`; a pre-release
/// suffix there would be a name with no file, so the stricter form is the one
/// that is checked before the path is formed.
pub fn legacy_version(value: &str) -> bool {
    let mut count = 0;
    for component in value.split('.') {
        count += 1;
        if !numeric_component(component) {
            return false;
        }
    }
    count >= 3
}

/// The fold rule of §1.3: ASCII lowercase.
///
/// The grammar admits no non-ASCII character, so this is the whole fold for a
/// legal document; it exists because the builder does not assume every path it
/// is handed came from this grammar (a discovered directory entry, or a
/// registry row). Two paths that fold to the same string in one domain collide.
pub fn fold(value: &str) -> String {
    value.to_ascii_lowercase()
}

/// Whether a segment is a Windows device name, case-insensitively, with or
/// without an extension.
pub fn is_device_name(segment: &str) -> bool {
    let base = segment
        .split('.')
        .next()
        .unwrap_or(segment)
        .to_ascii_uppercase();
    match base.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" => true,
        _ => {
            let bytes = base.as_bytes();
            bytes.len() == 4
                && (base.starts_with("COM") || base.starts_with("LPT"))
                && (b'1'..=b'9').contains(&bytes[3])
        }
    }
}

/// `ADR-0128` §1: a flat set field has exactly one legal spelling, strictly
/// increasing under code-point order.
///
/// This is a format check, not a set comparison: two arrays with the same
/// members and different order are different documents with different digests,
/// so the builder refuses the non-canonical one instead of sorting it.
pub fn strictly_increasing(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn starts_lowercase(value: &str) -> bool {
    value
        .bytes()
        .next()
        .map(|byte| byte.is_ascii_lowercase())
        .unwrap_or(false)
}

fn numeric_component(value: &str) -> bool {
    match value.as_bytes() {
        [b'0'] => true,
        [first, rest @ ..] => {
            first.is_ascii_digit()
                && *first != b'0'
                && rest.iter().all(|byte| byte.is_ascii_digit())
        }
        [] => false,
    }
}

fn portable_segment(segment: &str) -> bool {
    let mut bytes = segment.bytes();
    match bytes.next() {
        Some(first) if first.is_ascii_lowercase() || first.is_ascii_digit() || first == b'_' => {}
        _ => return false,
    }
    bytes.all(|byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || byte == b'_'
            || byte == b'.'
            || byte == b'-'
    })
}
