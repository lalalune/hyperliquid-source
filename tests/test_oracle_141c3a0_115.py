r"""Byte-level oracle test for node #115 routine 0x141c3a0 (RE-001).

This confronts the hand model (tools/backslash_root_prefix_141c3a0_115.py)
with an independent pure-Python interpreter of the routine's 51 raw
bytes (static; nothing native is executed), read from the digest-pinned
#115 target (artifacts/node/115/hl-node, else work/hl-node-115.bin).
It REQUIRES that target; when it is absent it raises unittest.SkipTest and
exits 0 so it never fails a binary-less run. The pure-model test,
tests/test_backslash_root_prefix_141c3a0_115.py, keeps running
without the binary and is unaffected.

Run directly (`python3 tests/test_oracle_141c3a0_115.py`) or through
tools/run_tests.py, which routes this script-style file to a direct
interpreter invocation. Prints "<n> checks pass" on success.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-backslash-root-prefix-141c3a0-115"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
CANDIDATES = (ROOT / "artifacts" / "node" / "115" / "hl-node",
              ROOT / "work" / "hl-node-115.bin")


def _target():
    """First candidate that is the digest-pinned #115 ELF (not an LFS pointer)."""
    import hashlib
    for path in CANDIDATES:
        if path.is_file() and path.stat().st_size > 1 << 20:
            if hashlib.sha256(path.read_bytes()).hexdigest() == DIGEST:
                return path
    return None

sys.path.insert(0, str(PACKET))
sys.path.insert(0, str(ROOT / "tools"))

CHECKS = [0]


def check(condition, label):
    assert condition, label
    CHECKS[0] += 1


def main():
    BINARY = _target()
    if BINARY is None:
        raise unittest.SkipTest("node #115 target absent; oracle test needs the target")

    import oracle_compare

    text, summary, controls = oracle_compare.build_report(str(BINARY))

    # Every enumerated buffer: interpreter al == model boolean.
    check(summary["mismatches"] == [], "no interpreter/model mismatch")
    check(summary["matches"] == summary["total"],
          "all %d buffers match" % summary["total"])
    check(summary["total"] >= 11111, "exhaustive len 0..4 pool present")

    # Bounds / read-index proof.
    check(summary["oob"] == [], "no out-of-bounds read")
    check(summary["max_read_index"] == 3, "max index read is 3")
    check(summary["read_ge4"] == [], "never reads index >= 4")
    check(summary["idx3_when_short"] == [], "byte[3] read only when len > 3")

    # Each corruption patch must diverge from the model.
    check(len(controls) == 4, "four corruption controls")
    for c in controls:
        check(c["divergences"] > 0,
              "patch diverges: %s" % c["label"])
        check(len(c["witnesses"]) > 0,
              "patch has a witness: %s" % c["label"])

    # The unpatched/patched contrast is the whole point: unpatched is 0
    # mismatches, patched is many.
    check(all(c["divergences"] >= 1 for c in controls),
          "all patched routines diverge while the real one matches 100%")

    # Stored results file is a deterministic render.
    stored = (PACKET / "oracle_results.txt").read_text()
    check(text == stored, "oracle_results.txt matches a fresh render")

    # assert_healthy encodes the same invariants; must not raise.
    oracle_compare.assert_healthy(summary, controls)
    CHECKS[0] += 1

    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    try:
        main()
    except unittest.SkipTest as exc:
        print("SKIP: %s" % exc)
        sys.exit(0)
