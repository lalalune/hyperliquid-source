"""Tests for node #115's span-count predicate at 0x5f6ea90.

Each case is a target-grounded expectation read off the verbatim
disassembly in research/work-items/RE-001-span-count-predicate-115/.
Run from the repository root: python3 tests/test_span_count_predicate_115.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from span_count_predicate_115 import (  # noqa: E402
    loop_steps, site_disposition, span_count_predicate)

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-span-count-predicate-115"
MAGIC = 0xAAAAAAAAAAAAAAAB
MASK64 = (1 << 64) - 1


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

    # Shifted span 3 (byte span 384) times the magic is 1.
    check("span 384 field 1 matches",
          span_count_predicate({0x00: 1, 0x08: 0x1000, 0x10: 0x1000 + 384}), 1)
    count += 1
    check("span 384 field 2 misses",
          span_count_predicate({0x00: 2, 0x08: 0x1000, 0x10: 0x1000 + 384}), 0)
    count += 1
    # Shifted span 384 (byte span 49152) times the magic is 128.
    check("span 49152 field 128 matches",
          span_count_predicate({0x00: 128, 0x08: 0, 0x10: 49152}), 1)
    count += 1
    # Zero span: shifted 0, product 0, so field 0 matches.
    check("zero span field 0 matches",
          span_count_predicate({0x00: 0, 0x08: 0x5000, 0x10: 0x5000}), 1)
    count += 1
    check("zero span field 1 misses",
          span_count_predicate({0x00: 1, 0x08: 0x5000, 0x10: 0x5000}), 0)
    count += 1
    # Non-multiple shifted spans are NOT divisions: shifted 4
    # times the magic is 0xAAAAAAAAAAAAAAAC, not 1.
    check("shifted 4 product is magic multiple",
          span_count_predicate(
              {0x00: 0xAAAAAAAAAAAAAAAC, 0x08: 0, 0x10: 512}), 1)
    count += 1
    check("shifted 4 field 1 misses",
          span_count_predicate({0x00: 1, 0x08: 0, 0x10: 512}), 0)
    count += 1
    # Shifted 5 times the magic is 0x5555555555555557.
    check("shifted 5 product",
          span_count_predicate(
              {0x00: 0x5555555555555557, 0x08: 0, 0x10: 640}), 1)
    count += 1
    # Sub-byte-span: byte span below 128 shifts to 0.
    check("span 127 shifts to zero",
          span_count_predicate({0x00: 0, 0x08: 0x2000, 0x10: 0x2000 + 127}), 1)
    count += 1
    # Negative span: arithmetic shift. Byte span -128 shifts to
    # -1, whose magic product is 0x5555555555555555.
    check("negative span -128",
          span_count_predicate(
              {0x00: 0x5555555555555555, 0x08: 0x2000, 0x10: 0x2000 - 128}), 1)
    count += 1
    # Negative span -384 shifts to -3, product 0xFFFFFFFFFFFFFFFF.
    check("negative span -384",
          span_count_predicate(
              {0x00: 0xFFFFFFFFFFFFFFFF, 0x08: 0x2000, 0x10: 0x2000 - 384}), 1)
    count += 1
    # Large addresses wrap in 64-bit subtraction, as in the binary.
    check("wrapping span",
          span_count_predicate(
              {0x00: 1, 0x08: MASK64 - 100, 0x10: 283}), 1)
    count += 1
    # Missing-field guards: a partially known record must not
    # silently model.
    expect_raises("missing first field", span_count_predicate,
                  {0x08: 0, 0x10: 384})
    count += 1
    expect_raises("missing begin", span_count_predicate,
                  {0x00: 1, 0x10: 384})
    count += 1
    expect_raises("missing end", span_count_predicate,
                  {0x00: 1, 0x08: 0})
    count += 1
    # Site disposition, end to end: predicate result through the
    # caller gate, the loop and the follow-up call.
    check("site false goes to cleanup",
          site_disposition(0, 0x1000, 0x2000, 0), "cleanup")
    count += 1
    check("site true empty zero stack byte follows up",
          site_disposition(1, 0x1000, 0x1000, 0), "followup")
    count += 1
    check("site true empty nonzero stack byte blocks",
          site_disposition(1, 0x1000, 0x1000, 1), "block-0x5fa1674")
    count += 1
    check("site true one step loops then follows up",
          site_disposition(1, 0x1000, 0x1000 + 0x180, 0),
          "loop:1:followup")
    count += 1
    check("site true three steps",
          site_disposition(1, 0x1000, 0x1000 + 3 * 0x180, 0),
          "loop:3:followup")
    count += 1
    check("loop steps helper", loop_steps(0x1000, 0x1000 + 2 * 0x180), 2)
    count += 1
    expect_raises("loop steps empty", loop_steps, 0x1000, 0x1000)
    count += 1
    expect_raises("loop steps unaligned", loop_steps, 0x1000, 0x1000 + 0x100)
    count += 1
    expect_raises("loop steps inverted", loop_steps, 0x2000, 0x1000)
    count += 1
    # Packet checks: the semantic records name the predicate, its
    # sole site and the digest-bound artifact.
    records = json.loads((PACKET / "records.json").read_text())
    check("records task", records["task"], "RE-001")
    count += 1
    check("records predicate address",
          records["predicate"]["address"], "0x5f6ea90")
    count += 1
    check("records sole site",
          records["call_sites"][0]["site"], "0x5fa159d")
    count += 1
    check("records digest", records["artifact_sha256"],
          "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    count += 1

    print("%d checks passed" % count)


if __name__ == "__main__":
    main()
