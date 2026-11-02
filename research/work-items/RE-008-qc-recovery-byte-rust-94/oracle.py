#!/usr/bin/env python3
"""Prepare independent input/expected corpora; no Rust or target execution.

--self-check verifies only corpus/comparator behavior using synthetic output
records. A compiled implementation comparison requires --check-outputs FILE.
"""

import argparse
import csv
from dataclasses import dataclass, replace
import hashlib
from pathlib import Path


PACKET = Path(__file__).resolve().parents[3] / "research/work-items/RE-008-qc-recovery-byte-94"
BOUNDARIES_SHA256 = "a0de4a8bdc454cb0580aa53403289f77b1f149f0b467657321b59c48e77ddd56"
FREEZE_SHA256 = "1ccb7ed05a6b95cf1854eb5caccae54277daa99ef4956bd4a842d92d640f657d"
MAX = (1 << 64) - 1
COUNT = 12 + 5 * 2 * 256


@dataclass(frozen=True)
class Case:
    name: str
    mode: int
    charge: int
    limit: int
    data: bytes
    status: str
    after: int
    consumed: int
    value: int | None
    kind: int | None
    error_word: int | None

    def input_line(self):
        return "\t".join(map(str, (self.name, self.mode, self.charge, self.limit, self.data.hex() or "-")))

    def expected_line(self):
        fields = (self.name, self.status, self.after, self.consumed,
                  len(self.data) - self.consumed,
                  self.data[self.consumed:].hex() or "-",
                  self.value, self.kind, self.error_word)
        return "\t".join("-" if value is None else str(value) for value in fields)


def frozen_cases():
    source = PACKET / "boundaries.csv"
    if hashlib.sha256(source.read_bytes()).hexdigest() != BOUNDARIES_SHA256:
        raise ValueError("frozen pre-model boundary table identity changed")
    if hashlib.sha256((PACKET / "freeze.json").read_bytes()).hexdigest() != FREEZE_SHA256:
        raise ValueError("pre-model native windows changed")
    rows = list(csv.DictReader(source.open()))
    if len(rows) != 12:
        raise ValueError("expected twelve frozen boundaries")
    result = []
    for row in rows:
        number = lambda key: None if row[key] == "-" else int(row[key])
        count, byte = number("remaining"), number("byte")
        # First byte comes from the frozen table; deterministic extra input
        # exposes accidental overconsumption without influencing the result.
        data = bytes((byte, byte ^ 0xA5))[:count] if count else b""
        if count not in (0, 1, 2):
            raise ValueError("unexpected frozen input length")
        kind = number("kind")
        result.append(Case(
            row["name"], number("mode"), number("charge"), number("limit"), data,
            row["status"], number("charge_after"), number("consumed"), number("value"),
            # Both native error branches prepare EDX=1 before O+0x10 store;
            # only kind0 gives this word the established shortfall meaning.
            kind, 1 if row["status"] == "error" else None,
        ))
    return result


def byte_cases():
    # Expected results are a piecewise relation, authored separately from the
    # Rust checked_add/split_first control flow. No packet Python model import.
    regimes = (
        ("mode0", 0, MAX, 0),
        ("mode2", 2, MAX, 0),
        ("admitted", 1, 2, 3),
        ("equal-limit", 1, 3, 3),
        ("overflow", 1, MAX, MAX),
    )
    for label, mode, charge, limit in regimes:
        for size in (1, 2):
            for value in range(256):
                data = bytes((value, value ^ 0xA5))[:size]
                after = charge if mode != 1 or charge == MAX else charge + 1
                denied = mode == 1 and (charge == MAX or charge >= limit)
                yield Case(f"byte-{label}-{size}-{value:03d}", mode, charge, limit, data,
                           "error" if denied else "ok", after, 0 if denied else 1,
                           None if denied else value, 2 if denied else None, 1 if denied else None)


def corpus():
    cases = frozen_cases() + list(byte_cases())
    if len(cases) != COUNT or len({case.name for case in cases}) != COUNT:
        raise ValueError("corpus count or uniqueness changed")
    return cases


def compare(cases, text):
    lines = text.splitlines()
    expected = [case.expected_line() for case in cases]
    if len(lines) != len(expected):
        raise ValueError(f"output count: expected {len(expected)}, got {len(lines)}")
    for index, (actual, wanted) in enumerate(zip(lines, expected), 1):
        if actual != wanted:
            raise ValueError(f"output {index}: expected {wanted!r}; got {actual!r}")


def self_check(cases):
    # Synthetic comparator sensitivity controls; none evaluates Rust or target.
    expected = [case.expected_line() for case in cases]
    compare(cases, "\n".join(expected) + "\n")
    by_name = {case.name: index for index, case in enumerate(cases)}
    mutations = (
        ("charged-overflow", {"after": 0}),
        ("charged-limit-equality", {"after": 3}),
        ("charged-empty", {"after": 2}),
        ("charged-limit-zero", {"kind": 0}),
        ("uncharged-empty", {"error_word": 2}),
        ("uncharged-ff", {"consumed": 2}),
        ("charged-boundary-success", {"value": 254}),
        ("charged-boundary-success", {"kind": 2}),
    )
    for name, changes in mutations:
        altered = expected.copy()
        index = by_name[name]
        altered[index] = replace(cases[index], **changes).expected_line()
        try:
            compare(cases, "\n".join(altered))
        except ValueError:
            pass
        else:
            raise ValueError(f"comparator admitted mutation {name} {changes}")
    for altered in (expected[:-1], expected + [expected[-1]], expected[1:] + expected[:1]):
        try:
            compare(cases, "\n".join(altered))
        except ValueError:
            pass
        else:
            raise ValueError("comparator admitted omission, duplicate, or reorder")
    inputs = "\n".join(case.input_line() for case in cases) + "\n"
    for line in inputs.splitlines():
        fields = line.split("\t")
        if len(fields) != 5:
            raise ValueError("driver input includes non-input fields")
    print(f"comparator-only self-check: {len(cases)} cases; 11 malformed-output controls rejected")
    print(f"input corpus sha256: {hashlib.sha256(inputs.encode()).hexdigest()}")
    print("Rust was not compiled or executed; target was not executed or interpreted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--emit-inputs", action="store_true")
    action.add_argument("--check-outputs", type=Path)
    action.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    cases = corpus()
    if args.emit_inputs:
        print("\n".join(case.input_line() for case in cases))
    elif args.check_outputs:
        compare(cases, args.check_outputs.read_text())
        print(f"candidate-output comparison: {len(cases)} records match")
    else:
        self_check(cases)


if __name__ == "__main__":
    main()
