"""Tests for node #115's record-fill routine at 0x5f6eb50.

Each case is a target-grounded expectation read off the verbatim
disassembly in research/work-items/RE-001-record-fill-115/.
Run from the repository root: python3 tests/test_record_fill_115.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from record_fill_115 import record_fill  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-record-fill-115"


def check(name, actual, expected):
    if actual != expected:
        raise AssertionError("%s: got %r, want %r" % (name, actual, expected))


def expect_raises(name, func, *args):
    try:
        func(*args)
    except ValueError:
        return
    raise AssertionError("%s: expected ValueError" % name)


def fresh_dst(gate):
    return {0x58: 0, 0x60: 0xDEAD, 0x70: 0, 0x7C: 0, 0x7D: 0,
            0x7F: 0, 0x134: gate}


def main():
    count = 0

    # Zero-gate arm: the four unconditional writes happen, the
    # oracle is never called, and +0x7d/+0x60 are left alone.
    calls = []
    src = {0xD8: 0x1122334455667788, 0x40: 0x9999}
    dst = fresh_dst(0)
    record_fill(src, dst, 0xAABBCCDDEEFF0011, calls.append)
    check("zero gate dst+0x58", dst[0x58], 0x1122334455667788)
    check("zero gate dst+0x70", dst[0x70], 0xAABBCCDDEEFF0011)
    check("zero gate dst+0x7c", dst[0x7C], 1)
    check("zero gate dst+0x7f", dst[0x7F], 1)
    check("zero gate dst+0x7d untouched", dst[0x7D], 0)
    check("zero gate dst+0x60 untouched", dst[0x60], 0xDEAD)
    check("zero gate oracle not called", calls, [])
    count += 1

    # Nonzero-gate arm: oracle called with (src+0x40, dst), then
    # +0x7d set and the 32-bit return stored at +0x60.
    seen = []
    src = {0xD8: 0, 0x40: 0x4242}
    dst = fresh_dst(0xFF)
    record_fill(src, dst, 0, lambda a, d: seen.append((a, d)) or 0x12345678)
    check("nonzero gate oracle arg", seen[0][0], 0x4242)
    check("nonzero gate oracle got dst", seen[0][1] is dst, True)
    check("nonzero gate dst+0x7d", dst[0x7D], 1)
    check("nonzero gate dst+0x60", dst[0x60], 0x12345678)
    count += 1

    # The 32-bit store truncates: only the low dword is kept.
    dst = fresh_dst(1)
    record_fill({0xD8: 5, 0x40: 7}, dst, 9,
                lambda a, d: 0x1_00000002)
    check("32-bit truncation at +0x60", dst[0x60], 2)
    count += 1

    # Zero src+0xd8 and zero pointer qword copy through unchanged.
    dst = fresh_dst(0)
    record_fill({0xD8: 0, 0x40: 1}, dst, 0, lambda a, d: 0)
    check("zero copy dst+0x58", dst[0x58], 0)
    check("zero copy dst+0x70", dst[0x70], 0)
    count += 1

    # Missing-field guards: src+0xd8 and dst+0x134 are always
    # required; src+0x40 is required only on the nonzero-gate arm,
    # so its absence is harmless on the zero arm.
    expect_raises("missing src+0xd8", record_fill, {}, fresh_dst(0),
                  0, lambda a, d: 0)
    bad = fresh_dst(0)
    del bad[0x134]
    expect_raises("missing dst+0x134", record_fill, {0xD8: 1}, bad,
                  0, lambda a, d: 0)
    dst = fresh_dst(0)
    record_fill({0xD8: 1}, dst, 0, lambda a, d: 0)
    check("zero arm needs no src+0x40", dst[0x58], 1)
    expect_raises("missing src+0x40 on taken arm", record_fill,
                  {0xD8: 1}, fresh_dst(3), 0, lambda a, d: 0)
    count += 1

    # Packet checks: semantic records only, bound to the digest,
    # with the single census site.
    records = json.loads((PACKET / "records.json").read_text())
    check("records task", records["task"], "RE-001")
    check("records node", records["node"], 115)
    check("records routine", records["routine"]["address"], "0x5f6eb50")
    check("records census",
          records["census"]["routine_0x5f6eb50"]["direct_calls"],
          ["0x5f95d03"])
    check("records callee", records["routine"]["callee"].split()[0],
          "0x5d8d0c0")
    if "endbr64" in json.dumps(records):
        raise AssertionError("records carry instruction-level detail")
    count += 1

    print("%d model checks passed" % count)


if __name__ == "__main__":
    main()
