"""Tests for node #115's flag-variant index leaf at 0x5f6b740.

Each case is a target-grounded expectation read off the verbatim
disassembly in research/work-items/RE-001-flag-variant-115/.
Run from the repository root: python3 tests/test_flag_variant_115.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from flag_variant_115 import flag_variant, site_disposition  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-flag-variant-115"


def check(name, actual, expected):
    if actual != expected:
        raise AssertionError("%s: got %r, want %r" % (name, actual, expected))


def expect_raises(name, func, *args):
    try:
        func(*args)
    except ValueError:
        return
    raise AssertionError("%s: expected ValueError" % name)


def main():
    count = 0

    # Zero-flag arm returns field - 1; nonzero-flag arm field - 2.
    check("zero flag basic", flag_variant({0x10: 10}, 0), 9)
    count += 1
    check("nonzero flag basic", flag_variant({0x10: 10}, 1), 8)
    count += 1
    check("flag 0xff nonzero", flag_variant({0x10: 10}, 0xFF), 8)
    count += 1
    # Only the low byte of the flag participates.
    check("flag 0x100 acts as zero", flag_variant({0x10: 10}, 0x100), 9)
    count += 1
    check("flag 0x101 acts as one", flag_variant({0x10: 10}, 0x101), 8)
    count += 1
    # Wrapping edges, modulo 2**32.
    check("field 0 zero flag wraps", flag_variant({0x10: 0}, 0), 0xFFFFFFFF)
    count += 1
    check("field 0 nonzero flag wraps", flag_variant({0x10: 0}, 7), 0xFFFFFFFE)
    count += 1
    check("field 2 zero flag to one", flag_variant({0x10: 2}, 0), 1)
    count += 1
    check("field 2 nonzero flag to zero", flag_variant({0x10: 2}, 3), 0)
    count += 1
    check("field 1 zero flag to zero", flag_variant({0x10: 1}, 0), 0)
    count += 1
    check("field 1 nonzero flag wraps to max",
          flag_variant({0x10: 1}, 1), 0xFFFFFFFF)
    count += 1
    check("field max zero flag", flag_variant({0x10: 0xFFFFFFFF}, 0),
          0xFFFFFFFE)
    count += 1
    check("field max nonzero flag", flag_variant({0x10: 0xFFFFFFFF}, 9),
          0xFFFFFFFD)
    count += 1
    # The two arms differ by exactly 1 for the same field.
    for field in (0, 1, 2, 100, 0x80000000, 0xFFFFFFFF):
        diff = (flag_variant({0x10: field}, 0)
                - flag_variant({0x10: field}, 1)) & 0xFFFFFFFF
        check("arm gap field %#x" % field, diff, 1)
        count += 1
    # Missing-field guard: a partially known record must not
    # silently model.
    expect_raises("missing field", flag_variant, {}, 0)
    count += 1
    # Site disposition, end to end: leaf result through the
    # caller comparison and the virtual-call gate.
    check("site mismatch away",
          site_disposition(flag_variant({0x10: 10}, 0), 8, 1), "away")
    count += 1
    check("site match virtual zero away",
          site_disposition(flag_variant({0x10: 10}, 0), 9, 0), "away")
    count += 1
    check("site match virtual negative away",
          site_disposition(flag_variant({0x10: 10}, 0), 9, -1), "away")
    count += 1
    check("site match virtual positive continues",
          site_disposition(flag_variant({0x10: 10}, 0), 9, 1), "continue")
    count += 1
    check("site nonzero-flag match continues",
          site_disposition(flag_variant({0x10: 10}, 5), 8, 42), "continue")
    count += 1
    # Packet checks: digest-bound semantic records, single site.
    records = json.loads((PACKET / "records.json").read_text())
    check("records digest", records["artifact_sha256"],
          "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    count += 1
    check("records task", records["task"], "RE-001")
    count += 1
    check("records census",
          records["census"]["leaf_0x5f6b740"]["direct_calls"], ["0x5df5bff"])
    count += 1
    check("records carry no instruction detail",
          "endbr64" in json.dumps(records), False)
    count += 1

    print("%d checks passed" % count)


if __name__ == "__main__":
    main()
