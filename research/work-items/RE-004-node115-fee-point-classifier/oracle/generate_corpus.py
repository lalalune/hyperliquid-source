#!/usr/bin/env python3
"""Deterministic scalar-only corpus builder for the reviewed mathematical reference.

Execution requires the separate parent review gate. This program never reads a
captured binary, decodes instructions, invokes subprocesses or uses a network.
Independent expected rows are pinned and preserved, not fitted to the reference.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import sys

import reference_math as reference

REFERENCE_SHA256 = "0ff857a3dd0e972bde5a361d3959b5706ca7c28485792b0550ad35d2af4a46d2"
HANDCASE_SHA256 = "69c664f6626d1cdbd5205c0ad4eb5111fd1215cbc7de375090a7f5d3f1b3928f"
SEED = b"node115-fee-point-precode-v1"
MAX_REQUESTED_CASES = 8192
U64_MAX = (1 << 64) - 1
HEX = re.compile(r"[0-9a-f]{16}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9_-]+\Z")
FIELDS = ("t", "d", "q", "m", "h")
SCALES = (
    0x3FF0000000000000, 0x3FC999999999999A, 0x4018000000000000,
    0x3FB999999999999A, 0x4000000000000000, 0x4044000000000000,
)
CLASSES = {
    "FirstProductNegative", "NetAndBaseNegative", "SecondProductNegative",
    "RoundedMagnitudeAtLeastQuantity", "Pass",
}
QUANTITIES = (1, 2, 3, 7, 10, 127, 128, 255, 256, 1023, 1024, 65535, 65536, 9999999, 10000000)
AXIS_QUANTITIES = (1, 10000000)
ALPHABET = (
    0x0000000000000000, 0x8000000000000000,
    0x0000000000000001, 0x8000000000000001,
    0x000FFFFFFFFFFFFF, 0x800FFFFFFFFFFFFF,
    0x0010000000000000, 0x8010000000000000,
    0x3FB999999999999A, 0xBFB999999999999A,
    0x3FE0000000000000, 0xBFE0000000000000,
    0x3FEFFFFFFFFFFFFF, 0xBFEFFFFFFFFFFFFF,
    0x3FF0000000000000, 0xBFF0000000000000,
    0x3FF0000000000001, 0xBFF0000000000001,
    0x433FFFFFFFFFFFFF, 0xC33FFFFFFFFFFFFF,
    0x4340000000000000, 0xC340000000000000,
    0x43DFFFFFFFFFFFFF, 0xC3DFFFFFFFFFFFFF,
    0x43E0000000000000, 0xC3E0000000000000,
    0x7FEFFFFFFFFFFFFF, 0xFFEFFFFFFFFFFFFF,
    0x7FF0000000000000, 0xFFF0000000000000,
    0x7FF8000000000123, 0x7FF0000000000001,
)
# Context tuples are t,d,q,m,h in that order.
CONTEXTS = (
    (0, 0, 0, 0, 0),
    (0x3FF0000000000000, 0, 0, 0, 0),
    (0x3FF0000000000000, 0, 0x3FE0000000000000, 0, 0x3FD0000000000000),
)
EXPONENTS = (0, 1, 2, 1022, 1023, 1024, 1075, 1085, 1086, 2045, 2046, 2047)
SIGNIFICANDS = (0, 1, (1 << 52) - 1, 0x5555555555555)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def parse_bits(text):
    if not isinstance(text, str) or not HEX.fullmatch(text):
        raise ValueError("expected exactly sixteen lowercase hex digits")
    return int(text, 16)


def point(quantity, scale, values):
    if type(quantity) is not int or not 1 <= quantity <= 10000000:
        raise ValueError("quantity outside the admitted domain")
    if type(scale) is not int or scale not in SCALES:
        raise ValueError("scale outside the six exact encodings")
    if len(values) != 5 or any(type(x) is not int or not 0 <= x <= U64_MAX for x in values):
        raise ValueError("five unsigned64 scalar encodings required")
    return (quantity, scale, *values)


def classify(p):
    quantity, scale, t, d, q, m, h = p
    actual = reference.classify_point(quantity=quantity, scale=scale, t=t, d=d, q=q, m=m, h=h)
    if actual not in CLASSES:
        raise ValueError("reference produced an unsupported class")
    return actual


def hash_word(family, index, field):
    payload = SEED + b"\0" + family.encode("ascii") + b"\0" + str(index).encode("ascii") + b"\0" + field.encode("ascii")
    return int.from_bytes(hashlib.sha256(payload).digest()[:8], "big")


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def gzip_bytes(raw):
    destination = io.BytesIO()
    with gzip.GzipFile(fileobj=destination, mode="wb", filename="", mtime=0, compresslevel=9) as stream:
        stream.write(raw)
    return destination.getvalue()


class Corpus:
    def __init__(self):
        self.records = []
        self.first_by_point = {}
        self.requested_ids = set()
        self.aliases = []
        self.family_requests = Counter()

    def add(self, case_id, p, family, *, independent=None):
        if not IDENTIFIER.fullmatch(case_id) or case_id in self.requested_ids:
            raise ValueError("invalid or duplicate requested case ID")
        self.requested_ids.add(case_id)
        if len(self.requested_ids) > MAX_REQUESTED_CASES:
            raise ValueError("hard requested-case cap exceeded")
        self.family_requests[family] += 1
        p = point(p[0], p[1], p[2:])
        # Every hand row is retained even if two independent rows happen to
        # share an input. Generated duplicates keep a first-occurrence alias.
        if independent is None and p in self.first_by_point:
            existing = self.first_by_point[p]
            existing["families"].add(family)
            self.aliases.append({"requested_case_id": case_id,
                                 "retained_case_id": existing["case_id"], "family": family})
            return
        actual = classify(p)
        if independent is not None:
            expected = independent["expected_first_class"]
            if expected not in CLASSES or actual != expected:
                raise ValueError(f"independent expectation mismatch for {case_id}: expected {expected}, actual {actual}")
            provenance = {"kind": "independent_handcase", "fixture_sha256": HANDCASE_SHA256,
                          "fixture_id": independent["id"], "reference_agreement_required": True}
            coverage = independent.get("coverage", [])
        else:
            expected = actual
            provenance = {"kind": "authored_exact_rational_reference", "reference_sha256": REFERENCE_SHA256}
            coverage = []
        record = {"case_id": case_id, "point": p, "expected": expected,
                  "expected_provenance": provenance, "families": {family},
                  "independent_coverage_labels": coverage}
        self.records.append(record)
        self.first_by_point.setdefault(p, record)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--handcases", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    if options.output.exists():
        raise FileExistsError("output path already exists; refusing to overwrite")
    if not options.output.parent.is_dir():
        raise ValueError("output parent must already exist")
    reference_raw = Path(reference.__file__).read_bytes()
    if digest(reference_raw) != REFERENCE_SHA256:
        raise ValueError("reviewed reference source hash differs")
    generator_raw = Path(__file__).read_bytes()
    hand_raw = options.handcases.read_bytes()
    if digest(hand_raw) != HANDCASE_SHA256:
        raise ValueError("independent handcase file hash differs")
    hand_document = json.loads(hand_raw)
    if hand_document["schema"] != "independent-fee-point-handcases-v1":
        raise ValueError("independent handcase schema differs")
    handcases = hand_document["cases"]
    if len(handcases) != 36:
        raise ValueError("exactly the sealed36 independent cases are required")

    corpus = Corpus()
    manual_points = []
    for case in handcases:
        inp = case["input"]
        if set(inp) != {"quantity", "scale_bits", "t_bits", "d_bits", "q_bits", "m_bits", "h_bits"}:
            raise ValueError("handcase input is not the scalar-only schema")
        p = point(inp["quantity"], parse_bits(inp["scale_bits"]),
                  tuple(parse_bits(inp[field + "_bits"]) for field in FIELDS))
        corpus.add(case["id"], p, "independent_handcases", independent=case)
        manual_points.append((case["id"], p))

    # A deliberate exact-2**64 unsigned-total boundary. The input is fixed;
    # its expected class is still produced only by the reviewed reference.
    # The parent is separately sealing an independent algebraic check.
    corpus.add("interaction_u64_exact_wrap", point(1, SCALES[0],
               (0, 0, 0x3FF0000000000000, 0x4000000000000000, 0x43E0000000000000)),
               "arithmetic_interactions")

    # Broad quantity boundaries in three explicitly defined mathematical contexts.
    for context_index, values in enumerate(CONTEXTS):
        for scale_index, scale in enumerate(SCALES):
            for quantity in QUANTITIES:
                corpus.add(f"quantity_b{context_index}_s{scale_index}_n{quantity}",
                           point(quantity, scale, values), "quantity_boundaries")

    # Fixed exact-bit alphabet on each individual scalar, at both quantity ends.
    for context_index in (0, 2):
        context = CONTEXTS[context_index]
        for field_index, field in enumerate(FIELDS):
            for alphabet_index, value in enumerate(ALPHABET):
                values = list(context)
                values[field_index] = value
                for scale_index, scale in enumerate(SCALES):
                    for quantity in AXIS_QUANTITIES:
                        corpus.add(f"axis_b{context_index}_{field}_a{alphabet_index}_s{scale_index}_n{quantity}",
                                   point(quantity, scale, values), "scalar_axis_boundaries")

    # Preserve the sealed witness and explore raw-bit/quantity/scale neighbors.
    # No expected label for a neighbor is inferred from the witness's label.
    for original_id, p in manual_points:
        quantity, scale, *original_values = p
        for field_index, field in enumerate(FIELDS):
            for delta, name in ((-1, "m1"), (1, "p1")):
                candidate = original_values[field_index] + delta
                if 0 <= candidate <= U64_MAX:
                    values = list(original_values)
                    values[field_index] = candidate
                    corpus.add(f"neighbor_{original_id}_{field}_{name}", point(quantity, scale, values), "handcase_neighbors")
        for delta, name in ((-1, "m1"), (1, "p1")):
            if 1 <= quantity + delta <= 10000000:
                corpus.add(f"neighbor_{original_id}_n_{name}", point(quantity + delta, scale, original_values), "handcase_neighbors")
        for scale_index, alternate in enumerate(SCALES):
            if alternate != scale:
                corpus.add(f"neighbor_{original_id}_s{scale_index}", point(quantity, alternate, original_values), "handcase_neighbors")

    # Independent per-field hash words, with exact namespace/counter encoding.
    for index in range(1024):
        values = tuple(hash_word("raw_bits", index, field) for field in FIELDS)
        quantity = 1 + hash_word("raw_bits", index, "quantity") % 10000000
        scale = SCALES[hash_word("raw_bits", index, "scale") % len(SCALES)]
        corpus.add(f"raw_{index:04d}", point(quantity, scale, values), "deterministic_arbitrary_bits")

    # Structured exponent/significand classes, each rotated through every field.
    index = 0
    for exponent in EXPONENTS:
        for sign in (0, 1):
            for significand in SIGNIFICANDS:
                value = (sign << 63) | (exponent << 52) | significand
                for field_index, field in enumerate(FIELDS):
                    values = list(CONTEXTS[index % len(CONTEXTS)])
                    values[field_index] = value
                    quantity = QUANTITIES[index % len(QUANTITIES)]
                    scale = SCALES[index % len(SCALES)]
                    corpus.add(f"stratified_{index:04d}_{field}", point(quantity, scale, values), "exponent_stratification")
                    index += 1

    if len(corpus.records) < 36 or len(corpus.records) > MAX_REQUESTED_CASES:
        raise ValueError("retained corpus count outside bounds")
    classes = Counter(record["expected"] for record in corpus.records)
    if set(classes) != CLASSES:
        raise ValueError("corpus must contain every approved class")
    if {record["point"][1] for record in corpus.records} != set(SCALES):
        raise ValueError("corpus must contain every scale")
    quantities = [record["point"][0] for record in corpus.records]
    if min(quantities) != 1 or max(quantities) != 10000000:
        raise ValueError("corpus must retain both admitted quantity boundaries")

    inputs, expected, metadata = [], [], []
    family_membership = Counter()
    for record in corpus.records:
        case_id = record["case_id"]
        quantity, scale, t, d, q, m, h = record["point"]
        inputs.append("\t".join([case_id, str(quantity)] + [f"{value:016x}" for value in (scale, t, d, q, m, h)]) + "\n")
        expected.append(case_id + "\t" + record["expected"] + "\n")
        families = sorted(record["families"])
        family_membership.update(families)
        metadata.append(canonical_json({"case_id": case_id, "families": families,
                                        "expected_provenance": record["expected_provenance"],
                                        "independent_coverage_labels": record["independent_coverage_labels"]}) + "\n")
    input_raw = "".join(inputs).encode("ascii")
    expected_raw = "".join(expected).encode("ascii")
    metadata_raw = "".join(metadata).encode("ascii")
    alias_raw = "".join(canonical_json(row) + "\n" for row in corpus.aliases).encode("ascii")
    outputs = {
        "inputs.tsv.gz": gzip_bytes(input_raw),
        "expected.tsv.gz": gzip_bytes(expected_raw),
        "case-metadata.jsonl.gz": gzip_bytes(metadata_raw),
        "input-aliases.jsonl.gz": gzip_bytes(alias_raw),
        "independent-handcases.original.json": hand_raw,
    }
    summary = {
        "schema": "fee-point-pre-source-corpus-v1",
        "seed_ascii": SEED.decode("ascii"),
        "hash_derivation": "SHA256(seed+NUL+family+NUL+ASCII decimal index+NUL+field), first8bytes big-endian",
        "requested_cases": len(corpus.requested_ids),
        "retained_cases": len(corpus.records),
        "generated_duplicate_aliases": len(corpus.aliases),
        "independent_rows_retained": len(handcases),
        "independent_expectations_unchanged": True,
        "family_requested_counts": dict(sorted(corpus.family_requests.items())),
        "family_retained_membership_counts": dict(sorted(family_membership.items())),
        "class_counts": dict(sorted(classes.items())),
        "scale_bits": [f"{x:016x}" for x in SCALES],
        "quantity_min": min(quantities), "quantity_max": max(quantities),
        "input_fields": ["case_id", "quantity", "scale_bits", "t_bits", "d_bits", "q_bits", "m_bits", "h_bits"],
        "expected_and_actual_fields": ["case_id", "class"],
        "transport": "ASCII TSV, no header, LF terminated, lowercase16hex scalar bits, canonical decimal quantity",
        "expected_field_in_input": False,
        "reference_sha256": REFERENCE_SHA256,
        "generator_sha256": digest(generator_raw),
        "independent_fixture_sha256": HANDCASE_SHA256,
        "python_version": sys.version,
        "gzip": {"filename": "", "mtime": 0, "compresslevel": 9},
        "uncompressed_sha256": {"inputs.tsv": digest(input_raw), "expected.tsv": digest(expected_raw),
                                 "case-metadata.jsonl": digest(metadata_raw), "input-aliases.jsonl": digest(alias_raw)},
        "native_execution": False, "all60million_pairs_enumerated": False,
        "whole_helper_or_runtime_equivalence": False,
        "reference_qualification": "External parent qualification receipts are required; this generator pins source and independently rechecks the36 hand classes.",
        "coverage_limit": "Family labels and output counts are not native branch coverage, exhaustive input coverage, effects or allocation qualification.",
    }
    outputs["SUMMARY.json"] = (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode("utf8")

    # All comparison work and data construction succeed before any output write.
    # A new directory is required; partial I/O failures are preserved, not hidden.
    options.output.mkdir()
    identities = []
    for filename, payload in outputs.items():
        destination = options.output / filename
        with destination.open("xb") as stream:
            stream.write(payload)
        if destination.read_bytes() != payload:
            raise OSError("written output bytes differ")
        identities.append({"path": filename, "bytes": len(payload), "sha256": digest(payload)})
    manifest = "".join(row["sha256"] + "  " + row["path"] + "\n" for row in sorted(identities, key=lambda row: row["path"]))
    with (options.output / "MANIFEST.sha256").open("x", encoding="ascii") as stream:
        stream.write(manifest)
    print(json.dumps({"retained_cases": len(corpus.records), "requested_cases": len(corpus.requested_ids),
                      "class_counts": dict(sorted(classes.items())), "files": identities,
                      "manifest_sha256": digest(manifest.encode("ascii")), "native_execution": False},
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
