#!/usr/bin/env python3
"""Derive outputs.tsv from the stated call-boundary results in inputs.tsv.

All numeric input qwords are parsed as hexadecimal: despite the decimal claim
in SPEC.md, the file contains hexadecimal letters and hexadecimal boundary
patterns.  Output qwords are written in decimal.  For tag 00 the four active
payload qwords are reported; the other copied qwords are uninitialized stack
contents, as documented in TRACE.md.  Dropping a validator result is assumed
to complete normally, which requires a valid record and allocator state.
"""

import csv
from pathlib import Path


HERE = Path(__file__).resolve().parent
U64_MAX = (1 << 64) - 1
INPUT_FIELDS = [
    "id", "head", "a", "b", "c", "d", "e", "tail", "ctx_c", "ctx_d",
    "helper", "validator",
]
OUTPUT_FIELDS = ["id", "out_tag", "out_words", "helper_calls", "validator_calls", "ref"]


def hex_u64(value):
    if not value or len(value) > 16 or any(c not in "0123456789abcdefABCDEF" for c in value):
        raise ValueError(f"invalid hexadecimal u64: {value!r}")
    n = int(value, 16)
    if n > U64_MAX:
        raise ValueError(f"u64 overflow: {value!r}")
    return n


def decimal_words(values):
    return ":".join(str(value) for value in values)


def calculate(row):
    head = row["head"].split(":")
    if len(head) != 4:
        raise ValueError(f"{row['id']}: expected four head words")
    for value in head:
        hex_u64(value)
    a, b, c, d, e, ctx_c, ctx_d = (
        hex_u64(row[key]) for key in ("a", "b", "c", "d", "e", "ctx_c", "ctx_d")
    )
    tail = bytes.fromhex(row["tail"])
    if len(tail) != 32:
        raise ValueError(f"{row['id']}: expected 32 tail bytes")
    if row["helper"] not in ("T", "F"):
        raise ValueError(f"{row['id']}: invalid helper result")

    validator = row["validator"]
    if validator == "A":
        validator_tag = "2e"
    else:
        parts = validator.split(":")
        if len(parts) != 3 or parts[0] != "R" or len(parts[1]) != 2:
            raise ValueError(f"{row['id']}: invalid validator result")
        tag_value = hex_u64(parts[1])
        hex_u64(parts[2])
        if tag_value > 255 or tag_value == 0x2E:
            raise ValueError(f"{row['id']}: invalid rejection tag")
        validator_tag = f"{tag_value:02x}"

    # Each result is tag, active payload words, helper calls, validator calls,
    # and the helper's second argument.  Address references are in TRACE.md.
    if (a, b) != (ctx_c, ctx_d):
        if a <= ctx_c:
            return "00", decimal_words((a, b, ctx_c, ctx_d)), 0, 0, "-"
        if validator == "A":
            return "noreturn", "-", 0, 1, "-"
        return "00", decimal_words((a, b, ctx_c, ctx_d)), 0, 1, "-"

    if c < b:
        return "05", "-", 0, 0, "-"
    if c == b:
        if d != b or e != b or any(tail):
            return "06", "-", 0, 0, "-"
        reference = (0, 8, 0, 0, a, b, b, b, b, 0, 0, 0, 0)
        return ("2e" if row["helper"] == "T" else "06"), "-", 1, 0, decimal_words(reference)

    if d < c and b <= e <= d:
        return validator_tag, "fwd", 0, 1, "-"
    return "2d", decimal_words((c, d, e)), 0, 0, "-"


def main():
    with (HERE / "inputs.tsv").open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source, delimiter="\t")
        if reader.fieldnames != INPUT_FIELDS:
            raise ValueError(f"unexpected input columns: {reader.fieldnames!r}")
        inputs = list(reader)
    ids = [row["id"] for row in inputs]
    if any(not identifier for identifier in ids) or len(ids) != len(set(ids)):
        raise ValueError("input IDs must be present and unique")

    with (HERE / "outputs.tsv").open("w", newline="", encoding="utf-8") as destination:
        writer = csv.writer(destination, delimiter="\t", lineterminator="\n")
        writer.writerow(OUTPUT_FIELDS)
        for row in inputs:
            writer.writerow((row["id"], *calculate(row)))
    print(f"outputs.tsv: {len(inputs) + 1} lines, including header; {len(inputs)} data rows")


if __name__ == "__main__":
    main()
