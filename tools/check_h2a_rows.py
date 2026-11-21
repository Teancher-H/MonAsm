# -*- coding: utf-8 -*-
"""Check that every N1a and N2 row of the H2a checklist names a real test.

The checklist is the execution index; a row that no test drives is a plan item
that is being reported as done without evidence. This script closes that gap
mechanically instead of by review:

- sections 2 (N1a) and 3 (N2) of
  `docs/architecture/he1-h2-acceptance-checklist.md` are read between their own
  headings, so inserting a section does not silently shrink the range;
- each row name must appear as `fn <name>(` in exactly one file under
  `prototype/crates/fmp-definition/tests/`;
- every `#[test] fn` in the `n1a_*.rs` and `n2_*.rs` files must be a row, so a
  test cannot drift from the checklist in the other direction either.

Rows of later sections are not checked here; each node adds its own range when it
lands, and N3 is where section 4 starts.
"""

import glob
import os
import re
import sys

CHECKLIST = "docs/architecture/he1-h2-acceptance-checklist.md"
TESTS = "prototype/crates/fmp-definition/tests"
NODE_FILES = ("n1a_*.rs", "n2_*.rs")


def section(text, start_heading, end_heading):
    start = text.index(start_heading)
    end = text.index(end_heading)
    return text[start:end]


def test_functions(source):
    """Only `#[test] fn` names count; helpers are not test rows."""
    names = []
    for match in re.finditer(r"#\[test\]\s*\n(?:#\[[^\]]*\]\s*\n)*fn ([a-z0-9_]+)\(", source):
        names.append(match.group(1))
    return names


def main():
    text = open(CHECKLIST, encoding="utf-8").read()
    n1a = section(text, "## 2. N1a", "## 3. N2")
    n2 = section(text, "## 3. N2", "## 4. N3")
    rows = re.findall(r"^- `([a-z0-9_]+)`", n1a, re.M) + re.findall(
        r"^- `([a-z0-9_]+)`", n2, re.M
    )
    if len(set(rows)) != len(rows):
        duplicates = sorted({name for name in rows if rows.count(name) > 1})
        print("FAIL duplicate checklist rows:", duplicates)
        return 1

    definitions = {}
    node_files = []
    for pattern in NODE_FILES:
        node_files.extend(sorted(glob.glob(os.path.join(TESTS, pattern))))
    for path in sorted(glob.glob(os.path.join(TESTS, "*.rs"))):
        source = open(path, encoding="utf-8").read()
        for name in test_functions(source):
            definitions.setdefault(name, []).append(path)

    missing = [name for name in rows if name not in definitions]
    duplicated = {
        name: paths for name, paths in definitions.items() if len(paths) > 1 and name in rows
    }

    unmapped = []
    for path in node_files:
        source = open(path, encoding="utf-8").read()
        for name in test_functions(source):
            if name not in rows:
                unmapped.append((os.path.basename(path), name))

    for name in missing:
        print("MISSING", name)
    for name, paths in duplicated.items():
        print("DUPLICATE", name, paths)
    for path, name in unmapped:
        print("UNMAPPED", path, name)

    if missing or duplicated or unmapped:
        return 1

    print(
        "OK: %d rows (%d N1a, %d N2), each named by exactly one test in %s"
        % (
            len(rows),
            len(re.findall(r"^- `([a-z0-9_]+)`", n1a, re.M)),
            len(re.findall(r"^- `([a-z0-9_]+)`", n2, re.M)),
            os.path.basename(TESTS) + "/*.rs",
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
