#!/usr/bin/env python3
"""Read-only comparison against the independently sealed scalar hand fixtures.

No expected value is generated or modified. Only classification strings and
explicit isolated primitive results are compared. Handwritten intermediate
traces are retained in the input file but are not computed by this driver.
Parent effect/correctness approval is required before execution.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

import reference_math as reference

CANDIDATE_SHA256 = "69c664f6626d1cdbd5205c0ad4eb5111fd1215cbc7de375090a7f5d3f1b3928f"
PRIMITIVE_SHA256 = "22e92a987c27df081e8a2873ff26915730c16916026da2dc8b92b0a1ad018465"
CLASSIFICATIONS = {
    "FirstProductNegative", "NetAndBaseNegative", "SecondProductNegative",
    "RoundedMagnitudeAtLeastQuantity", "Pass",
}
HEX = re.compile(r"[0-9a-f]{16}\Z")
I64_MIN, I64_MAX = -(1 << 63), (1 << 63) - 1
U64_MAX = (1 << 64) - 1


def bits(text):
    if not isinstance(text, str) or not HEX.fullmatch(text):
        raise ValueError("bits must be sixteen lower-case hex digits")
    return int(text, 16)


def signed(value):
    if type(value) is not int or not I64_MIN <= value <= I64_MAX:
        raise ValueError("expected an i64 integer")
    return value


def unsigned(value):
    if type(value) is not int or not 0 <= value <= U64_MAX:
        raise ValueError("expected a u64 integer")
    return value


def read_pinned(path, wanted, schema, key):
    raw = path.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != wanted:
        raise ValueError(f"fixture identity mismatch: {path.name}: {actual}")
    document = json.loads(raw)
    if document["schema"] != schema:
        raise ValueError("fixture schema mismatch")
    rows = document[key]
    if not isinstance(rows, list) or not rows:
        raise ValueError("nonempty fixture list required")
    identifiers = [row["id"] for row in rows]
    if any(not isinstance(x, str) or not x for x in identifiers):
        raise ValueError("nonempty string IDs required")
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("duplicate fixture IDs")
    return rows


def classify(case):
    inp = case["input"]
    required = {"quantity", "scale_bits", "t_bits", "d_bits", "q_bits", "m_bits", "h_bits"}
    if set(inp) != required:
        raise ValueError("candidate input fields differ from scalar-only schema")
    expected = case["expected_first_class"]
    if expected not in CLASSIFICATIONS:
        raise ValueError("unknown independent expected class")
    actual = reference.classify_point(
        quantity=inp["quantity"], scale=bits(inp["scale_bits"]),
        t=bits(inp["t_bits"]), d=bits(inp["d_bits"]), q=bits(inp["q_bits"]),
        m=bits(inp["m_bits"]), h=bits(inp["h_bits"]),
    )
    return expected, actual, "complete numerical class only; intermediate hand trace not computed"


def primitive(case):
    op = case["operation"]
    scope = "isolated authored reference primitive; no full-path reachability inferred"
    if op == "finite_nonfinite_conversion":
        actual = reference.nonfinite_zero_integer(bits(case["input_bits"]))
    elif op == "i64_to_binary64_RN_even":
        actual = reference.rounded_i64(signed(case["input_integer"]))
    elif op == "binary64_multiply_RN_even":
        actual = reference.rn_mul(bits(case["left_bits"]), bits(case["right_bits"]))
    elif op == "sat_i64_subtract":
        actual = reference._saturate_i64(signed(case["left_integer"]) - signed(case["right_integer"]))
    elif op == "sat_i64_add":
        actual = reference._saturate_i64(signed(case["left_integer"]) + signed(case["right_integer"]))
    elif op == "unsigned_i64_magnitude":
        actual = abs(signed(case["input_integer"]))
        scope = "Python exact-integer magnitude expression also used by the projection; primitive-only, not a reached MIN witness"
    elif op == "u64_add_without_carry":
        actual = unsigned(case["left_integer"]) + unsigned(case["right_integer"])
        unsigned(actual)
        scope = "Python exact unsigned sum expression; its no-carry domain is checked, not a native runtime observation"
    elif op == "sat_u64_add":
        actual = min(U64_MAX, unsigned(case["left_integer"]) + unsigned(case["right_integer"]))
        scope = "Python exact unsigned saturation expression also used by the projection; no native effect claim"
    else:
        raise ValueError("unknown independent primitive operation")

    expected_keys = {"expected_integer", "expected_bits", "expected_category"} & set(case)
    if len(expected_keys) != 1:
        raise ValueError("exactly one independent expectation required")
    kind = next(iter(expected_keys))
    expected = case[kind]
    if kind == "expected_bits":
        bits(expected)
        actual = f"{actual:016x}"
    elif kind == "expected_category":
        if expected != "NaN":
            raise ValueError("only the sealed NaN category is supported")
        exponent = (actual >> 52) & 0x7FF
        fraction = actual & ((1 << 52) - 1)
        actual = "NaN" if exponent == 0x7FF and fraction else f"bits:{actual:016x}"
    elif type(expected) is not int:
        raise ValueError("integer expectation must be a JSON integer")
    return expected, actual, scope


def compare(rows, evaluator):
    observations, failures, errors = [], [], []
    for row in rows:
        try:
            expected, actual, scope = evaluator(row)
            observation = {"id": row["id"], "expected": expected, "actual": actual,
                           "matched": expected == actual, "scope": scope}
            if "candidate_reachability" in row:
                observation["independent_reachability_note"] = row["candidate_reachability"]
            observations.append(observation)
            if not observation["matched"]:
                failures.append(observation)
        except Exception as error:
            errors.append({"id": row["id"], "error": type(error).__name__, "message": str(error)})
    return {"rows": len(rows), "observations": observations, "mismatches": failures, "errors": errors,
            "passed": not failures and not errors}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("candidates", type=Path)
    parser.add_argument("primitives", type=Path)
    options = parser.parse_args()
    candidate_rows = read_pinned(options.candidates, CANDIDATE_SHA256,
                                 "independent-fee-point-handcases-v1", "cases")
    primitive_rows = read_pinned(options.primitives, PRIMITIVE_SHA256,
                                 "independent-fee-point-primitives-v1", "fixtures")
    candidate_result = compare(candidate_rows, classify)
    primitive_result = compare(primitive_rows, primitive)
    candidate_result["expected_class_counts"] = dict(Counter(row["expected_first_class"] for row in candidate_rows))
    candidate_result["actual_class_counts"] = dict(Counter(row["actual"] for row in candidate_result["observations"]))
    passed = candidate_result["passed"] and primitive_result["passed"]
    result = {
        "schema": "fee-reference-independent-qualification-v1",
        "candidate_fixture_sha256": CANDIDATE_SHA256,
        "primitive_fixture_sha256": PRIMITIVE_SHA256,
        "reference_sha256": hashlib.sha256(Path(reference.__file__).read_bytes()).hexdigest(),
        "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "python_version": sys.version,
        "candidates": candidate_result,
        "primitives": primitive_result,
        "passed": passed,
        "native_execution": False,
        "hand_intermediate_values_checked": False,
        "whole_helper_or_runtime_equivalence": False,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
