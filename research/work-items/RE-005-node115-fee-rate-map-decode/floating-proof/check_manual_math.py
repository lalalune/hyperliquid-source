"""Check prewritten scalar witnesses with exact rational values, never target code.

Only MANUAL-WITNESSES-v1.json is read.  No floating point, native bytes,
instruction records, project imports, network, subprocess or dynamic imports.
The integer test checks nearest neighbours around an already-authored answer;
it does not derive that answer by the proposed production rounding algorithm.
"""
import hashlib
import json
from collections import Counter
from fractions import Fraction
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WITNESS_SHA = "89ded30a86078ee19c84109f5370c86d54ab8d6bb5fd260d0f694d02b8bdd7de"


def pow2(n):
    return Fraction(1 << n) if n >= 0 else Fraction(1, 1 << -n)


def binary_value(bits, exponent_bits, fraction_bits, bias):
    sign = bits >> (exponent_bits + fraction_bits)
    exponent = (bits >> fraction_bits) & ((1 << exponent_bits) - 1)
    fraction = bits & ((1 << fraction_bits) - 1)
    if exponent == (1 << exponent_bits) - 1:
        raise ValueError("nonfinite has no rational value")
    magnitude = (Fraction(fraction) * pow2(1 - bias - fraction_bits)
                 if exponent == 0 else
                 Fraction((1 << fraction_bits) + fraction) *
                 pow2(exponent - bias - fraction_bits))
    return -magnitude if sign else magnitude


def binary64_value(bits):
    return binary_value(bits, 11, 52, 1023)


def require(condition, description):
    if not condition:
        raise AssertionError(description)


def nearest_integer(n, expected):
    sign = int(n < 0)
    require(expected >> 63 == sign, "integer answer sign")
    magnitude = expected & ((1 << 63) - 1)
    require(magnitude < 0x7ff0000000000000, "integer answer finite")
    distance = abs(binary64_value(magnitude) - abs(n))
    neighbours = [magnitude + 1]
    if magnitude:
        neighbours.append(magnitude - 1)
    for neighbour in neighbours:
        other_distance = abs(binary64_value(neighbour) - abs(n))
        require(distance <= other_distance, "nearest adjacent representable")
        if distance == other_distance:
            require(magnitude & 1 == 0, "ties choose even significand")
    return "exact-rational-neighbour-distance-and-tie-parity"


def check_row(row):
    expected = int(row["expected_binary64_hex"], 16)
    require(len(row["expected_binary64_hex"]) == 16, "64-bit answer width")
    kind = row["kind"]
    if kind in ("u64", "i64"):
        n = int(row["input"])
        require(0 <= n < 1 << 64 if kind == "u64" else
                -(1 << 63) <= n < 1 << 63, "integer domain")
        return nearest_integer(n, expected)
    if kind == "binary64_raw":
        require(expected == int(row["input"], 16), "64-bit raw identity")
        return "raw-bit-identity"
    require(kind == "binary32", "known witness kind")
    raw = int(row["input"], 16)
    require(0 <= raw < 1 << 32, "32-bit raw domain")
    sign, exponent, fraction = raw >> 31, (raw >> 23) & 255, raw & 0x7fffff
    require(expected >> 63 == sign, "original sign restoration")
    if exponent < 255:
        require(binary64_value(expected) == binary_value(raw, 8, 23, 127),
                "finite widening exact rational identity")
        return "exact-rational-finite-value-and-sign"
    if fraction == 0:
        require(expected == (sign << 63) | 0x7ff0000000000000,
                "infinity sign and exponent")
        return "infinity-bit-identity"
    require(expected == (sign << 63) | 0x7ff0000000000000 |
            (fraction << 29) | (1 << 51), "Intel Table D-11 NaN expansion")
    return "documented-NaN-payload-shift-and-quieting"


def main():
    raw = (ROOT / "MANUAL-WITNESSES-v1.json").read_bytes()
    require(hashlib.sha256(raw).hexdigest() == WITNESS_SHA, "frozen witness bytes")
    rows = json.loads(raw)["rows"]
    require(len(rows) == 62, "frozen witness count")
    require(len({r["id"] for r in rows}) == len(rows), "unique witness IDs")
    results = [{"id": r["id"], "relation": check_row(r), "passed": True}
               for r in rows]
    print(json.dumps({"witness_sha256": WITNESS_SHA, "count": len(rows),
        "kinds": dict(Counter(r["kind"] for r in rows)),
        "all_passed": True, "results": results,
        "limits": "Finite boundary witnesses plus exact rational checks; not all-input enumeration, target execution, ISA emulation, decoder corpus or exception-flag equivalence."},
        indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
