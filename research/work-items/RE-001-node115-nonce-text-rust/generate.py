#!/usr/bin/env python3
"""Deterministic pre-source corpus from grammar families, never native code.

Usage: python3 -B generate.py --out DIRECTORY
Outputs input-only TSV and separately computed expected TSV, both compressed.
The raw-byte/mode/depth domain is real; no instruction or helper execution is
part of generation. Oracle imports are the only local runtime dependency.
"""

import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import random

from oracle import Outcome, evaluate, input_line, output_line
from resource_policy import classify_required_length

SEED = 0x11513961694
MAX = (1 << 64) - 1


def candidates():
    # Small explicit anchors have independently written expected outcomes.
    anchors = [
        (b"", 1, 0, Outcome("not-admitted")),
        (b"[]", 1, 0, Outcome("parsed", 2, ())),
        (b" \t[]", 1, 0, Outcome("parsed", 4, ())),
        (b"\r\n[ \t]", 1, 0, Outcome("parsed", 6, ())),
        (b"[0]", 1, 0, Outcome("parsed", 3, (0,))),
        (b"[0,1]", 1, 0, Outcome("parsed", 5, (0, 1))),
        (b"[0, 1 ]", 1, 0, Outcome("parsed", 7, (0, 1))),
        (b"[18446744073709551615]", 1, 0, Outcome("parsed", 22, (MAX,))),
        (b"[0,18446744073709551615]", 1, 0, Outcome("parsed", 24, (0, MAX))),
        (b"[9223372036854775808]", 1, 0, Outcome("parsed", 21, (1 << 63,))),
        (b"[] \xff", 1, 0, Outcome("parsed", 2, ())),
        (b"[0]]", 1, 0, Outcome("parsed", 3, (0,))),
        (b"[0,1]junk", 1, 0, Outcome("parsed", 5, (0, 1))),
        (b"[0,0]", 1, 0, Outcome("order-invariant")),
        (b"[2,1]", 1, 0, Outcome("order-invariant")),
        (b"[2,1]x", 1, 0, Outcome("order-invariant")),
        (b"[2,1,]", 1, 0, Outcome("not-admitted")),
        (b"[2,1", 1, 0, Outcome("not-admitted")),
        (b"[2,1,18446744073709551616]", 1, 0, Outcome("not-admitted")),
        (b"[00]", 1, 0, Outcome("not-admitted")),
        (b"[-0]", 1, 0, Outcome("not-admitted")),
        (b"[+1]", 1, 0, Outcome("not-admitted")),
        (b"[0.0]", 1, 0, Outcome("not-admitted")),
        (b"[1e0]", 1, 0, Outcome("not-admitted")),
        (b"[18446744073709551616]", 1, 0, Outcome("not-admitted")),
        (b"\x0b[]", 1, 0, Outcome("not-admitted")),
        (b"[\x0c]", 1, 0, Outcome("not-admitted")),
        (b"[0,]", 1, 0, Outcome("not-admitted")),
        (b"[,]", 1, 0, Outcome("not-admitted")),
        (b"[0 1]", 1, 0, Outcome("not-admitted")),
        (b"[", 0, 0, Outcome("depth-zero")),
        (b"[", 0, 1, Outcome("depth-one")),
        (b"[", 0, 2, Outcome("not-admitted")),
        (b"", 0, 0, Outcome("not-admitted")),
        (b"]", 0, 1, Outcome("not-admitted")),
        (b"\x0b[", 0, 0, Outcome("not-admitted")),
        (b" \t[garbage", 0, 0, Outcome("depth-zero")),
        (b" \t[garbage", 0, 1, Outcome("depth-one")),
        (b"[]", 0, 2, Outcome("parsed", 2, ())),
        (b"[]", 255, 0, Outcome("parsed", 2, ())),
        (b"[]", 255, 1, Outcome("parsed", 2, ())),
    ]
    for number, (data, mode, depth, expected) in enumerate(anchors):
        yield "anchors", f"anchor-{number:03d}", mode, depth, data, expected

    # Exhausts the two raw bytes using one canonical empty spelling. It does
    # not multiply every other family by every pair or claim independent proof.
    for mode in range(256):
        for depth in range(256):
            yield "all-mode-depth", f"md-{mode:03d}-{depth:03d}", mode, depth, b"[]", None

    # All bytes in structurally distinct positions. Exact outputs include early
    # prefix closes (e.g. a ']' separator) instead of assuming suffix exhaustion.
    positions = [
        ("single", b"", b""),
        ("before-open", b"", b"[]"),
        ("empty-body", b"[", b"]"),
        ("before-number", b"[", b"0]"),
        ("after-zero", b"[0", b"]"),
        ("separator", b"[0", b"1]"),
        ("after-comma", b"[0,", b"1]"),
        ("before-close", b"[0,1", b"]"),
        ("trailing", b"[]", b""),
    ]
    for position, prefix, suffix in positions:
        for byte in range(256):
            yield "all-byte-positions", f"byte-{position}-{byte:02x}", 1, 0, prefix + bytes([byte]) + suffix, None

    openings = [b"", b" \t\r\n", b"]", b"x[", b"\x00[", b"\x0b[", b"\xff[", b"[", b"[garbage", b" \t[2,1,]", b"[2,1]", b" \t[]\xff"]
    for number, data in enumerate(openings):
        for mode in (0, 1, 2, 127, 128, 255):
            for depth in (0, 1, 2, 127, 128, 255):
                yield "depth-opening-priority", f"priority-{number:02d}-{mode:03d}-{depth:03d}", mode, depth, data, None

    boundaries = {0, 1, MAX, MAX + 1}
    for base in [10 ** exponent for exponent in range(21)] + [1 << bit for bit in range(66)]:
        boundaries.update(base + delta for delta in (-2, -1, 0, 1, 2) if base + delta >= 0)
    for number, value in enumerate(sorted(boundaries)):
        spelling = str(value).encode("ascii")
        for kind, word in (("unsigned", spelling), ("negative", b"-" + spelling), ("positive-sign", b"+" + spelling), ("leading-zero", b"0" + spelling)):
            yield "numeric-boundaries", f"number-{number:03d}-{kind}", 1, 0, b"[" + word + b"]", None

    spellings = [
        b"", b"-", b"+", b"--1", b"+-1", b"1-", b"01", b"00", b"000", b"0x1", b"0b1", b"0o1", b"1_0",
        b".0", b"0.", b"0.0", b"1.00", b"-0.0", b"18446744073709551615.0", b"1.2.3",
        b"0e0", b"1e0", b"1E0", b"1e+0", b"1E-0", b"1e", b"1e+", b"1e-", b"1e01", b"1e9999", b"1e-9999", b"1e1.0",
        b"NaN", b"nan", b"Infinity", b"inf", b"null", b"true", b"false", b'"1"', b"[]", b"{}", b"1\x002", b"\xff", b"\xc2\xa0", b"\xef\xbb\xbf1",
        b"9" * 5001, b"0" * 5001, b"1." + b"0" * 5001, b"1e" + b"9" * 5001,
    ]
    for number, word in enumerate(spellings):
        for position, data in (("only", b"[" + word + b"]"), ("later", b"[0," + word + b"]"), ("after-descending", b"[2,1," + word + b"]")):
            yield "numeric-spellings", f"spelling-{number:03d}-{position}", 1, 0, data, None

    delimiters = [
        b"[", b"[ ", b"[0", b"[0 ", b"[0,", b"[0, ", b"[0,]", b"[0, ]", b"[0,,1]", b"[,0]", b"[0;1]", b"[0:1]", b"[0 1]", b"[0\n1]",
        b"[0\r,\n1\t]", b"[[0]]", b"[0}[", b"[0,1}\xff", b"[0,1],garbage", b"[0,1] [garbage", b"[2,1,3,]", b"[2,1 3]", b"[2,1,3]", b"[2,1,3.0]", b"[2,1,3e0]",
        b"[0,0,]", b"[0,0,18446744073709551616]", b"[0,0]", b"\xef\xbb\xbf[]", b"\xc2\xa0[]", b"\xe2\x80\x83[]", b"[\xff]",
    ]
    for number, data in enumerate(delimiters):
        yield "delimiters-and-precedence", f"delimiter-{number:03d}", 1, 0, data, None

    for size in (0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257):
        ordered = list(range(size))
        variants = [("ordered", ordered)]
        if size >= 2:
            variants.extend((("duplicate-last", ordered[:-1] + [ordered[-2]]), ("descending-last", ordered[:-1] + [0])))
        for kind, values in variants:
            text = b"[" + b",".join(str(value).encode("ascii") for value in values)
            yield "sequence-boundaries", f"sequence-{size:03d}-{kind}", 1, 0, text + b"]", None
            if kind != "ordered":
                yield "sequence-boundaries", f"sequence-{size:03d}-{kind}-late-error", 1, 0, text + b",]", None

    rng = random.Random(SEED)
    for number in range(384):
        size = rng.randrange(65)
        data = bytes(rng.randrange(256) for _ in range(size))
        # Raw byte fuzz mainly challenges alphabet/opening rejection; structured
        # byte-position and mutation families carry delimiter/value coverage.
        yield "arbitrary-bytes", f"raw-{number:03d}", rng.randrange(256), rng.randrange(256), data, None
    seeds = [b"[]", b"[0]", b"[0,1]", b"[1,2,3]", b"[18446744073709551615]", b" \t[0, 1]\xff", b"[2,1,]"]
    for number in range(512):
        data = rng.choice(seeds)
        position = rng.randrange(len(data) + 1)
        op = number % 4
        byte = bytes([rng.randrange(256)])
        if op == 0:
            changed = data[:position] + byte + data[position:]
        elif op == 1:
            changed = data[:position] + byte + data[position + 1:]
        elif op == 2:
            changed = data[:position] + data[position + 1:]
        else:
            changed = data[:position]
        yield "structured-mutations", f"edit-{number:03d}", 1, 0, changed, None


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_gzip(path, content):
    # A GzipFile fixes header metadata independently of the zlib fast-path
    # behavior of gzip.compress across Python versions.
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as stream:
            stream.write(content)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out
    out.mkdir(parents=True, exist_ok=False)
    families = {}
    seen = set()
    inputs, expected = bytearray(), bytearray()
    checks, longest = 0, 0
    totals = Counter()
    for family, case_id, mode, depth, data, explicit in candidates():
        if case_id in seen:
            raise ValueError(f"duplicate case id {case_id}")
        seen.add(case_id)
        result = evaluate(data, mode, depth)
        if explicit is not None:
            if result != explicit:
                raise AssertionError((case_id, result, explicit))
            checks += 1
        inputs.extend(input_line(case_id, mode, depth, data).encode("ascii"))
        expected.extend(output_line(case_id, result).encode("ascii"))
        totals[result.kind] += 1
        longest = max(longest, len(data))
        info = families.setdefault(family, {"count": 0, "first_case": case_id, "last_case": case_id, "outcomes": Counter()})
        info["count"] += 1
        info["last_case"] = case_id
        info["outcomes"][result.kind] += 1
    write_gzip(out / "inputs.tsv.gz", bytes(inputs))
    write_gzip(out / "expected.tsv.gz", bytes(expected))

    resource_cases = []
    for bits in (16, 32, 64):
        host_max = ((1 << (bits - 1)) - 1) // 8
        points = {0, 1, 2, 3, 4, 5, 7, 8, 9, host_max - 1, host_max, host_max + 1, (1 << 59) - 1, 1 << 59, (1 << 59) + 1, (1 << 60) - 1, 1 << 60, (1 << 64) - 1, 1 << 64}
        for required in sorted(points):
            resource_cases.append(classify_required_length(required, bits))
    resource_doc = {
        "scope": "Chosen host admission arithmetic only; no memory reservation and no native OOM/error result.",
        "premise": "Required initialized words N <= 2^59 and 8*N <= host isize::MAX. Source spare capacity need not mirror native growth.",
        "future_validation": "Compare actual source capacity helper with these arithmetic expectations; actual fallible reserve failure remains a distinct own-host branch.",
        "cases": resource_cases,
    }
    (out / "resource-arithmetic.json").write_text(json.dumps(resource_doc, indent=2, sort_keys=True) + "\n")
    report = {
        "schema": "node115-nonce-text-pre-source-corpus-v1",
        "seed_decimal": SEED,
        "total_cases": len(seen),
        "literal_anchor_checks": checks,
        "maximum_input_bytes": longest,
        "outcomes": dict(sorted(totals.items())),
        "families": families,
        "wire_format": "Root admitted TSV; input hex or dash; parsed consumption/vector only on success.",
        "oracle_resource_premise": "Own checked capacity and fallible reservations succeed; resource arithmetic is separate.",
        "inputs_uncompressed_bytes": len(inputs),
        "inputs_uncompressed_sha256": sha(inputs),
        "expected_uncompressed_bytes": len(expected),
        "expected_uncompressed_sha256": sha(expected),
        "resource_cases": len(resource_cases),
        "files": {name: {"bytes": (out / name).stat().st_size, "sha256": sha((out / name).read_bytes())} for name in ("inputs.tsv.gz", "expected.tsv.gz", "resource-arithmetic.json")},
    }
    (out / "coverage.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
