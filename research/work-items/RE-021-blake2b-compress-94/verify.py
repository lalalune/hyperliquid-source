#!/usr/bin/env python3
"""Regenerate RE-021 with the tool and compare to the committed packet, exactly."""
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import blake2b_compress as tool  # noqa: E402

PACKET_JSON = HERE / "blake2b-compress.json"
JSON_SHA256 = "dc2420392ce8f7ad5f63dbc313b8ddb8095143a91a25eef1e9a2a7663ad78f92"


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
    print("verify: key_insns=%d vectors=%d rol_total=%d errors=%d" % (
        result["key_insns_count"],
        len(result["eip152_vectors"]),
        sum(result["rol_counts"].values()),
        len(errors)))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
