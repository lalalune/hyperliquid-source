"""Tests for node #115's gated de-accumulation leaf at 0x5f6b620.

Each case is a target-grounded expectation read off the verbatim
disassembly in research/work-items/RE-001-deaccum-leaf-115/.
Run from the repository root: python3 tests/test_deaccum_leaf_115.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from deaccum_leaf_115 import deaccumulate, deaccumulate_from_obj  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-deaccum-leaf-115"
MASK64 = (1 << 64) - 1


def check(name, actual, expected):
    if actual != expected:
        raise AssertionError("%s: got %r, want %r" % (name, actual, expected))


def main():
    # Flag byte zero: no mutation at all, returns False.
    base = {"fb0": 100, "fb8": 50, "fc0": 3}
    check("flag zero returns False",
          deaccumulate(base, {"b5": 0, "80": 10, "88": 30}), False)
    check("flag zero leaves base untouched", base,
          {"fb0": 100, "fb8": 50, "fc0": 3})
    # Basic apply: fb0 += 88 - 80, fc0 -= 1, fb8 -= 88.
    base = {"fb0": 100, "fb8": 50, "fc0": 3}
    check("flag nonzero returns True",
          deaccumulate(base, {"b5": 1, "80": 10, "88": 30}), True)
    check("basic fb0", base["fb0"], 120)
    check("basic fc0", base["fc0"], 2)
    check("basic fb8", base["fb8"], 20)
    # Any nonzero flag byte applies, including 0xFF.
    base = {"fb0": 0, "fb8": 0, "fc0": 1}
    check("flag 0xFF applies",
          deaccumulate(base, {"b5": 0xFF, "80": 0, "88": 0}), True)
    check("flag 0xFF fc0", base["fc0"], 0)
    # Wrapping 64-bit edges.
    base = {"fb0": 0, "fb8": 0, "fc0": 0}
    deaccumulate(base, {"b5": 1, "80": 1, "88": 0})
    check("wrap fb0", base["fb0"], MASK64)
    check("wrap fc0", base["fc0"], MASK64)
    check("wrap fb8 zero minus zero", base["fb8"], 0)
    base = {"fb0": 7, "fb8": 3, "fc0": 9}
    deaccumulate(base, {"b5": 1, "80": 0, "88": 5})
    check("wrap fb8", base["fb8"], MASK64 - 1)
    # Inverse relation: accumulate then deaccumulate restores the
    # three counters (accumulation-leaf updates, applied inline).
    base = {"fb0": 1000, "fb8": 500, "fc0": 42, "other": 77}
    elt = {"b5": 1, "80": 10, "88": 30}
    base["fb0"] = (base["fb0"] + elt["80"] - elt["88"]) & MASK64
    base["fb8"] = (base["fb8"] + elt["88"]) & MASK64
    base["fc0"] = (base["fc0"] + 1) & MASK64
    check("accumulate then deaccumulate applies",
          deaccumulate(base, elt), True)
    check("inverse fb0", base["fb0"], 1000)
    check("inverse fb8", base["fb8"], 500)
    check("inverse fc0", base["fc0"], 42)
    check("unrelated field untouched", base["other"], 77)
    # Missing-field guards.
    for bad_base in ({"fb8": 0, "fc0": 0}, {"fb0": 0, "fc0": 0},
                     {"fb0": 0, "fb8": 0}):
        try:
            deaccumulate(bad_base, {"b5": 1, "80": 0, "88": 0})
        except KeyError:
            pass
        else:
            raise AssertionError("missing base field not rejected")
    for bad_elt in ({"80": 0, "88": 0}, {"b5": 1, "88": 0},
                    {"b5": 1, "80": 0}):
        try:
            deaccumulate({"fb0": 0, "fb8": 0, "fc0": 0}, bad_elt)
        except KeyError:
            pass
        else:
            raise AssertionError("missing element field not rejected")
    # Caller-terms wrapper: obj+0xff0/+0xff8/+0x1000.
    obj = {"ff0": 100, "ff8": 50, "1000": 3}
    check("obj wrapper applies",
          deaccumulate_from_obj(obj, {"b5": 1, "80": 10, "88": 30}),
          True)
    check("obj ff0", obj["ff0"], 120)
    check("obj ff8", obj["ff8"], 20)
    check("obj 1000", obj["1000"], 2)
    obj = {"ff0": 100, "ff8": 50, "1000": 3}
    check("obj wrapper flag zero",
          deaccumulate_from_obj(obj, {"b5": 0, "80": 10, "88": 30}),
          False)
    check("obj wrapper flag zero untouched", obj,
          {"ff0": 100, "ff8": 50, "1000": 3})
    try:
        deaccumulate_from_obj({"ff8": 0, "1000": 0},
                              {"b5": 1, "80": 0, "88": 0})
    except KeyError:
        pass
    else:
        raise AssertionError("missing obj field not rejected")
    # Packet checks: semantic records carry the census and no
    # instruction-level detail.
    records = json.loads((PACKET / "records.json").read_text())
    check("records census direct calls",
          records["census"]["leaf_0x5f6b620"]["direct_calls"],
          ["0x5f53747", "0x5f537af", "0x5f5390a"])
    check("records census tail jumps",
          records["census"]["leaf_0x5f6b620"]["tail_jumps"],
          ["0x5f45d50", "0x5f45df6"])
    check("records call sites", len(records["call_sites"]), 5)
    if "endbr64" in json.dumps(records):
        raise AssertionError("records carry instruction-level detail")
    print("OK: 26 checks passed")


if __name__ == "__main__":
    main()
