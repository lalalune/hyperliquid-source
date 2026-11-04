#!/usr/bin/env python3
"""Read immutable mathematical fixtures and report exact primitive mismatches.

Only the sibling authored reference is imported. No captured artifact, external
program, network or build is consulted. Output is JSON on stdout; fixtures are
never rewritten. Execution requires the separate parent qualification gate.
"""
import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import re
import sys

import reference_math as reference

HEX = re.compile(r"[0-9a-f]{16}\Z")
DECIMAL = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")


def integer(text):
    if not isinstance(text, str) or not DECIMAL.fullmatch(text):
        raise ValueError("integer argument must be canonical decimal text")
    return int(text)


def bits(text):
    if not isinstance(text, str) or not HEX.fullmatch(text):
        raise ValueError("bit argument must be sixteen lower-case hex digits")
    return int(text, 16)


def evaluate(case):
    op, args = case["operation"], case["arguments"]
    if op == "round_ratio" and len(args) == 2:
        value = Fraction(integer(args[0]), integer(args[1]))
        return f"{reference.round_binary64(value):016x}"
    if op == "round_dyadic" and len(args) == 2:
        coefficient, power = map(integer, args)
        value = (Fraction(coefficient << power) if power >= 0
                 else Fraction(coefficient, 1 << -power))
        return f"{reference.round_binary64(value):016x}"
    if op == "sub" and len(args) == 2:
        return f"{reference.rn_sub(*map(bits, args)):016x}"
    if op == "mul" and len(args) == 2:
        return f"{reference.rn_mul(*map(bits, args)):016x}"
    if op == "rounded_i64" and len(args) == 1:
        return f"{reference.rounded_i64(integer(args[0])):016x}"
    if op == "nonfinite_zero_integer" and len(args) == 1:
        return str(reference.nonfinite_zero_integer(bits(args[0])))
    raise ValueError("unknown operation or incorrect argument count")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("fixtures", type=Path)
    options = parser.parse_args()
    raw = options.fixtures.read_bytes()
    document = json.loads(raw)
    if document["schema"] != "fee-reference-primitive-cases-v1":
        raise ValueError("unsupported fixture schema")
    cases = document["cases"]
    if not isinstance(cases, list) or not cases:
        raise ValueError("nonempty case list required")
    seen, mismatches, errors = set(), [], []
    for case in cases:
        name = case["id"]
        if not isinstance(name, str) or not name or name in seen:
            raise ValueError("case IDs must be nonempty and unique")
        seen.add(name)
        try:
            actual = evaluate(case)
        except Exception as error:
            errors.append({"id": name, "error": type(error).__name__,
                           "message": str(error)})
            continue
        if actual != case["expected"]:
            mismatches.append({"id": name, "expected": case["expected"],
                               "actual": actual})
    result = {
        "schema": "fee-reference-primitive-qualification-v1",
        "fixture_sha256": hashlib.sha256(raw).hexdigest(),
        "reference_sha256": hashlib.sha256(Path(reference.__file__).read_bytes()).hexdigest(),
        "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "python_version": sys.version,
        "case_count": len(cases),
        "mismatches": mismatches,
        "errors": errors,
        "passed": not mismatches and not errors,
        "scope": "authored exact-rational primitives against frozen hand expectations; no native execution",
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
