#!/usr/bin/env python3
"""Regenerate RE-020 with the tool and compare to the committed packet, exactly."""
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import path_field_thunk as tool  # noqa: E402

PACKET_JSON = HERE / "path-field-thunk.json"
JSON_SHA256 = "6d3a09f4d8ab2e6061c6bfe3491ccec5fa43ad4f15439999e743557ab1c3ce15"


def main():
    result = tool.analyse(tool.TARGET.read_bytes())
    text = tool.render(result)
    errors = list(tool.expectation_errors(result))
    if hashlib.sha256(text.encode()).hexdigest() != JSON_SHA256:
        errors.append("regenerated output sha256 mismatch")
    if PACKET_JSON.read_text() != text:
        errors.append("committed json differs from regenerated output")
    for e in errors:
        print("FAIL", e)
    print("verify: key_insns=%d ff15=%d e8_direct=%d locations=%d errors=%d" % (
        result["key_insns"], result["ff15_count"], result["e8_direct_to_thunk_count"],
        len(result["locations"]), len(errors)))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
