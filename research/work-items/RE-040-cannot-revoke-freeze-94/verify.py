#!/usr/bin/env python3
"""Regenerate RE-040 with the tool and compare to the committed packet."""
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import cannot_revoke_freeze as tool  # noqa: E402

PACKET_JSON = HERE / "cannot_revoke_freeze.json"
JSON_SHA256_PATH = HERE / "MANIFEST.sha256"


def expected_json_sha256():
    for line in JSON_SHA256_PATH.read_text().splitlines():
        digest, name = line.split(None, 1)
        if name.strip() == "cannot_revoke_freeze.json":
            return digest
    raise SystemExit("json sha missing from MANIFEST")


def main():
    result = tool.analyse(tool.TARGET.read_bytes())
    text = tool.render(result)
    errors = list(tool.expectation_errors(result))
    digest = hashlib.sha256(text.encode()).hexdigest()
    expect = expected_json_sha256()
    if digest != expect:
        errors.append("regenerated output sha256 mismatch")
    if PACKET_JSON.read_text() != text:
        errors.append("committed json differs from regenerated output")
    for e in errors:
        print("FAIL", e)
    print(
        "verify: key_insns=%d strings=%d direct_calls=%d errors=%d"
        % (
            len(result["key_insns"]),
            len(result["error_strings"]),
            result["direct_calls"],
            len(errors),
        )
    )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
