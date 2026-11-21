//! Rows whose whole content is a decision about a string, made before any open.
//!
//! These are the rows of the H2a checklist that can be decided on the declared
//! text alone: the package path, the portable path grammar, the full package
//! identifier in the directory name, and the legacy source components.

mod support;

use std::path::Path;

use fmp_definition::package::LoadedPackage;
use fmp_definition::{lexical, Manifest};
use support::{write_package, ManifestFixture, TempTree};

/// `a_package_path_cannot_escape_its_root` — the declared path is bounded before
/// a single `open`, so an escaping path is a content rejection (exit 1), not a
/// host failure, and it never reaches a filesystem that might resolve it.
#[test]
fn a_package_path_cannot_escape_its_root() {
    let cases = [
        "../packages/x86_64/monasm.x86.mov-register/0.1.0",
        "packages/../monasm.x86.mov-register/0.1.0",
        "packages/x86_64/../../monasm.x86.mov-register/0.1.0",
        "/packages/x86_64/monasm.x86.mov-register/0.1.0",
        "C:/packages/x86_64/monasm.x86.mov-register/0.1.0",
        "packages//x86_64/monasm.x86.mov-register/0.1.0",
        "packages/x86_64/monasm.x86.mov-register/0.1.0/extra",
        "packages/x86_64/monasm.x86.mov-register",
        "bundles/x86_64/monasm.x86.mov-register/0.1.0",
    ];
    for case in cases {
        let error = LoadedPackage::load(Path::new("."), case).expect_err(case);
        assert_eq!(error.code(), "path-lexical", "{case} -> {error}");
        assert_eq!(error.exit_code(), 1, "{case} -> {error}");
    }
}

/// `identifier_and_path_lexical_rules_are_platform_independent` — each fault is
/// a pure ASCII string decision, so ext4, APFS and NTFS give the same answer.
/// If any of these were left to the host, the same package would have two
/// meanings and `source_package_digest` would name two different trees.
#[test]
fn identifier_and_path_lexical_rules_are_platform_independent() {
    use lexical::PathFault;

    let faults = [
        // Uppercase is outside `pseg`; `README.md`/`NOTICE` are the only fixed
        // uppercase spellings and they are whole segments.
        ("Forms/add.json", PathFault::NotPortableSegment),
        ("forms/Add.json", PathFault::NotPortableSegment),
        ("forms//add.json", PathFault::EmptySegment),
        ("forms/add.json/", PathFault::EmptySegment),
        // A trailing dot or space is the same file on Windows and a different
        // one on ext4.
        ("forms/add./x.json", PathFault::TrailingDotOrSpace),
        ("forms/add.json ", PathFault::TrailingDotOrSpace),
        ("forms/add .json", PathFault::NotPortableSegment),
        // A device name opens something that is not a file on Windows. The
        // uppercase spelling is caught by the segment grammar first, which is
        // why the lowercase form is the one the device rule has to catch.
        ("forms/NUL.json", PathFault::NotPortableSegment),
        ("forms/nul.json", PathFault::DeviceName),
        ("forms/com1", PathFault::DeviceName),
        ("forms/lpt9.txt", PathFault::DeviceName),
        ("forms/../add.json", PathFault::ParentSegment),
        ("forms/./add.json", PathFault::ParentSegment),
        ("forms\\add.json", PathFault::Backslash),
        ("c:/add.json", PathFault::Absolute),
        ("", PathFault::Empty),
    ];
    for (value, expected) in faults {
        assert_eq!(lexical::path(value), Err(expected), "{value:?}");
    }
    for legal in [
        "forms/add.json",
        "forms/mov-r64-rm.json",
        "README.md",
        "docs/NOTICE",
        "evidence/legacy-source.md",
        "_private/x",
    ] {
        assert_eq!(lexical::path(legal), Ok(()), "{legal:?}");
    }

    for bad in [
        "Monasm.X86",
        "monasm..x86",
        "monasm.x86.",
        ".x86",
        "monasm",
        "monasm.x86 ",
        "monasm.x86.Ä",
        "monasm.-x86",
    ] {
        assert!(lexical::ident(bad).is_err(), "{bad:?}");
    }
    for good in ["monasm.x86.mov-register", "vendor.x86.crypto"] {
        assert_eq!(lexical::ident(good), Ok(()), "{good:?}");
    }
}

/// `a_package_path_keeps_the_full_package_id` — the directory segment is the
/// whole dotted identifier, so the namespace is part of the path: `monasm.x86`
/// and `vendor.x86` can both ship a `crypto` package, and a directory that
/// names a different package is a rejection rather than a silent retarget.
#[test]
fn a_package_path_keeps_the_full_package_id() {
    let tree = TempTree::new("full-id");

    let first = ManifestFixture {
        package_id: "monasm.x86.crypto".to_string(),
        ..ManifestFixture::default()
    };
    let first_relative = write_package(&tree, &first);
    assert_eq!(first_relative, "packages/x86_64/monasm.x86.crypto/0.1.0");
    let loaded =
        LoadedPackage::load(tree.root(), &first_relative).expect("the first package loads");
    assert_eq!(loaded.manifest().package_id(), "monasm.x86.crypto");

    let second = ManifestFixture {
        package_id: "vendor.x86.crypto".to_string(),
        ..ManifestFixture::default()
    };
    let second_relative = write_package(&tree, &second);
    assert_eq!(second_relative, "packages/x86_64/vendor.x86.crypto/0.1.0");
    let loaded =
        LoadedPackage::load(tree.root(), &second_relative).expect("the second package loads");
    assert_eq!(loaded.manifest().package_id(), "vendor.x86.crypto");

    // A directory whose last segment is not the manifest's package_id: the
    // package would otherwise be reachable under a name it does not declare.
    tree.write(
        "packages/x86_64/vendor.x86.other/0.1.0/package.json",
        first.text().as_bytes(),
    );
    let error = LoadedPackage::load(tree.root(), "packages/x86_64/vendor.x86.other/0.1.0")
        .expect_err("the directory name disagrees with the manifest");
    assert_eq!(error.code(), "path-lexical");
    assert!(
        error.to_string().contains("package_id"),
        "the rejection names the component: {error}"
    );
}

/// `the_legacy_source_path_components_are_strict` — `definitions/<isa>/<version>`
/// is assembled from two components, so each is checked as a component first.
/// A value that would add a separator, a dot or a pre-release suffix is rejected
/// before a path exists.
#[test]
fn the_legacy_source_path_components_are_strict() {
    for bad in ["x86-64", "x86.64", "X86", "", "x86_64/../x", "x86_64\\x"] {
        assert!(!lexical::legacy_isa(bad), "{bad:?}");
    }
    for good in ["x86_64", "aarch64", "rv64"] {
        assert!(lexical::legacy_isa(good), "{good:?}");
    }
    for bad in ["0.1", "0.1.0-h2", "01.0.0", "0.1.0.0x", "0.1.0/.."] {
        assert!(!lexical::legacy_version(bad), "{bad:?}");
    }
    for good in ["0.1.0", "0.78.0", "1.0.0"] {
        assert!(lexical::legacy_version(good), "{good:?}");
    }

    for (isa, version) in [
        ("x86-64", "0.1.0"),
        ("x86_64", "0.1.0-h2"),
        ("../x", "0.1.0"),
    ] {
        let fixture = ManifestFixture {
            legacy: Some((isa.to_string(), version.to_string())),
            ..ManifestFixture::default()
        };
        let error = Manifest::parse(fixture.text().as_bytes()).expect_err("a strict component");
        assert_eq!(error.code(), "path-lexical", "{isa:?} {version:?}");
    }
}
