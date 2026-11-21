# -*- coding: utf-8 -*-
"""Recompute the H2a digest vectors independently of the Rust implementation.

`ADR-0128` section 7.0 requires the fixed vector to reproduce in Rust *and* in
Python: the Rust test proves the implementation follows the ADR, and this script
proves the ADR's numbers can be reproduced from the bytes alone. Two
implementations that both read the fixture are not two sources, so the fixture
is itself checked against the ADR — every expected digest must still appear in
`docs/adr/0128-package-and-bundle-contract.md`.

The canonical strings in the fixture are the preimages. They are re-serialised
here with `sort_keys=True` and `(",", ":")` separators; if that changes a byte,
the recorded digest no longer describes a canonical document.
"""

import hashlib
import json
import sys

FIXTURE = "fixtures/h2a/digest-vectors.json"
ADR = "docs/adr/0128-package-and-bundle-contract.md"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def domain_digest(domain, body):
    payload = domain.encode("utf-8") + b"\x00" + body.encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def bare_digest(body):
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def main():
    fixture = json.load(open(FIXTURE, encoding="utf-8"))
    adr = open(ADR, encoding="utf-8").read()

    failures = []
    checks = 0

    def check(name, actual, expected):
        nonlocal checks
        checks += 1
        if actual != expected:
            failures.append("%s: got %s, expected %s" % (name, actual, expected))
        if expected not in adr:
            failures.append("%s: expected digest is not in %s" % (name, ADR))

    for vector in fixture["domain_vectors"]:
        name = vector["name"]
        body = vector["canonical"]
        parsed = json.loads(body)
        if canonical(parsed) != body:
            failures.append("%s: the preimage is not canonical JSON" % name)
            continue
        check(name, domain_digest(vector["domain"], body), vector["expected"])

    for vector in fixture["canonical_vectors"]:
        name = vector["name"]
        body = vector["canonical"]
        if canonical(json.loads(body)) != body:
            failures.append("%s: the preimage is not canonical JSON" % name)
            continue
        check(name, "sha256:" + bare_digest(body), vector["expected"])

    for vector in fixture["raw_vectors"]:
        check(vector["name"], bare_digest(vector["bytes"]), vector["expected"])

    for record in fixture["records"]:
        name = record["name"]
        assets = []
        for asset in record["assets"]:
            body = asset["canonical"]
            if canonical(json.loads(body)) != body:
                failures.append("%s/%s: the asset preimage is not canonical" % (name, asset["path"]))
                continue
            assets.append(
                {
                    "digest": "sha256:" + bare_digest(body),
                    "kind": asset["kind"],
                    "path": asset["path"],
                }
            )
        assets.sort(key=lambda asset: asset["path"])
        source = {"assets": assets, "manifest": json.loads(record["manifest"])}
        check(
            name,
            domain_digest("monasm-package/0.1", canonical(source)),
            record["expected_digest"],
        )

    # The literal `sha256:` text is part of the preimage. A record hashed with
    # 32 raw bytes is the mistake the vector exists to catch, so it is checked
    # here as a counterexample and must *not* reproduce the value.
    source_vector = next(v for v in fixture["domain_vectors"] if v["name"] == "source_package_digest")
    asset_hex = source_vector["canonical"].split("sha256:")[1][:64]
    raw = bytes.fromhex(asset_hex)
    if len(raw) != 32:
        failures.append("the asset digest is not 32 bytes of hex")
    body = source_vector["canonical"]
    marker = '"sha256:%s"' % asset_hex
    before, after = body.split(marker, 1)
    wrong = ('monasm-package/0.1' + '\x00' + before + '"').encode("utf-8")
    wrong += raw + ('"' + after).encode("utf-8")
    if hashlib.sha256(wrong).hexdigest() == source_vector["expected"][len("sha256:"):]:
        failures.append("raw digest bytes reproduced the vector; the text rule is not pinned")

    if failures:
        for failure in failures:
            print("FAIL", failure)
        return 1
    print(
        "OK: %d digest checks reproduced from the fixture, every expected value "
        "still present in the ADR" % checks
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
