"""Tests for node #115's storage-release leaf at 0x5f78000 and
container-clear leaf at 0x5f78030.

Each case is a target-grounded expectation read off the verbatim
disassembly in research/work-items/RE-001-teardown-pair-115/.
Run from the repository root: python3 tests/test_teardown_pair_115.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from teardown_pair_115 import (  # noqa: E402
    cleanup_sequence, clear_container, landing_sequence,
    release_storage)

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-teardown-pair-115"
MASK64 = (1 << 64) - 1


def check(name, actual, expected):
    if actual != expected:
        raise AssertionError("%s: got %r, want %r" % (name, actual, expected))


def main():
    count = 0

    # Release leaf: zero begin returns at once with no delete, and
    # the leaf writes nothing.
    obj = {0x00: 0, 0x10: 4096}
    check("release null begin", release_storage(obj), None)
    check("release null leaves fields alone", obj, {0x00: 0, 0x10: 4096})
    count += 1

    # Release leaf: nonzero begin deletes (begin, cap - begin).
    obj = {0x00: 0x1000, 0x10: 0x1400}
    check("release delete record", release_storage(obj),
          (0x1000, 0x400))
    check("release leaves fields alone", obj, {0x00: 0x1000, 0x10: 0x1400})
    count += 1

    # Release leaf: size wraps mod 2**64 when cap is below begin.
    obj = {0x00: 0x1000, 0x10: 0x800}
    check("release wrap size", release_storage(obj),
          (0x1000, MASK64 - 0x7FF))
    count += 1

    # Release leaf: equal begin and cap deletes with size zero.
    obj = {0x00: 0x1000, 0x10: 0x1000}
    check("release empty size", release_storage(obj), (0x1000, 0))
    count += 1

    # Release leaf: missing field raises instead of inventing state.
    try:
        release_storage({0x00: 0x1000})
        raise AssertionError("release missing field did not raise")
    except ValueError:
        count += 1

    # Clear leaf: nonzero first qword is nulled and end becomes
    # begin.
    obj = {0x00: 0x5000, 0x190: 0x2000, 0x198: 0x2800, 0x1A0: 0x3000}
    clear_container(obj)
    check("clear nulls first qword", obj[0x00], 0)
    check("clear end becomes begin", obj[0x198], 0x2000)
    check("clear begin untouched", obj[0x190], 0x2000)
    check("clear capacity untouched", obj[0x1A0], 0x3000)
    count += 1

    # Clear leaf: zero first qword with begin != end still clears
    # the sub-container.
    obj = {0x00: 0, 0x190: 0x2000, 0x198: 0x2800}
    clear_container(obj)
    check("clear zero-first still clears", obj[0x198], 0x2000)
    count += 1

    # Clear leaf: already-empty sub-container is a no-op.
    obj = {0x00: 0x5000, 0x190: 0x2000, 0x198: 0x2000}
    clear_container(obj)
    check("clear empty no-op first", obj[0x00], 0)
    check("clear empty no-op end", obj[0x198], 0x2000)
    count += 1

    # Clear leaf: missing field raises instead of inventing state.
    try:
        clear_container({0x00: 0, 0x190: 0x2000})
        raise AssertionError("clear missing field did not raise")
    except ValueError:
        count += 1

    # Cleanup sequence (0x5f7f280 entry order): release, clear,
    # release, in that order.
    first = {0x00: 0x1000, 0x10: 0x1400}
    middle = {0x00: 0x5000, 0x190: 0x2000, 0x198: 0x2800}
    third = {0x00: 0x2000, 0x10: 0x2400}
    deletes = []
    cleanup_sequence(first, middle, third, deletes)
    check("cleanup delete order", deletes,
          [(0x1000, 0x400), (0x2000, 0x400)])
    check("cleanup middle cleared first", middle[0x00], 0)
    check("cleanup middle end", middle[0x198], 0x2000)
    check("cleanup release fields untouched", first,
          {0x00: 0x1000, 0x10: 0x1400})
    count += 1

    # Cleanup sequence with null begins: no deletes, clear still
    # applied.
    first = {0x00: 0, 0x10: 0}
    middle = {0x00: 0x5000, 0x190: 0x2000, 0x198: 0x2800}
    third = {0x00: 0, 0x10: 0}
    deletes = []
    cleanup_sequence(first, middle, third, deletes)
    check("cleanup null deletes", deletes, [])
    check("cleanup null middle cleared", middle[0x198], 0x2000)
    count += 1

    # Landing sequence with the slot zero: release, clear, release
    # again on the same shared object.
    shared = {0x00: 0x1000, 0x10: 0x1800}
    cleared = {0x00: 0x5000, 0x190: 0x2000, 0x198: 0x2800}
    deletes = []
    landing_sequence(shared, cleared, True, deletes)
    check("landing double delete", deletes,
          [(0x1000, 0x800), (0x1000, 0x800)])
    check("landing cleared", cleared[0x198], 0x2000)
    count += 1

    # Landing sequence with the slot nonzero: one release only, the
    # second object untouched.
    shared = {0x00: 0x1000, 0x10: 0x1800}
    cleared = {0x00: 0x5000, 0x190: 0x2000, 0x198: 0x2800}
    deletes = []
    landing_sequence(shared, cleared, False, deletes)
    check("landing single delete", deletes, [(0x1000, 0x800)])
    check("landing skipped clear", cleared,
          {0x00: 0x5000, 0x190: 0x2000, 0x198: 0x2800})
    count += 1

    # Packet checks: records bind the digest and both censuses.
    records = json.loads((PACKET / "records.json").read_text())
    check("records digest", records["artifact_sha256"],
          "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    check("records release census",
          records["census"]["release_0x5f78000"]["direct_calls"],
          ["0x5f7f22f", "0x5f7f251", "0x5f7f28b", "0x5f7f2a0",
           "0x5f7f2fa"])
    check("records clear census",
          records["census"]["clear_0x5f78030"]["direct_calls"],
          ["0x5f7f247", "0x5f7f293"])
    check("records release field", records["release"]["reads"],
          ["obj+0x00 as begin", "obj+0x10 as capacity end"])
    check("records clear rule", records["clear"]["rule"],
          "store zero at obj+0x00 when that qword is nonzero; then "
          "store begin at obj+0x198 when begin differs from end")
    count += 1

    print("%d model checks passed" % count)


if __name__ == "__main__":
    main()
