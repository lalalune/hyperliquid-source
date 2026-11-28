"""Locate the first difference between pinned node #115 raw export trees."""

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re

U64_MAX = (1 << 64) - 1
DIGEST = re.compile(r"0x[0-9a-f]{64}")
SHA256 = re.compile(r"[0-9a-f]{64}")
FIELDS = {"height", "abci_digest", "exchange_abci_hash"}


@dataclass(frozen=True)
class Leaf:
    digest: str


@dataclass(frozen=True)
class Branch:
    rows: tuple


def decode_tree(value):
    if type(value) is str and DIGEST.fullmatch(value):
        return Leaf(value)
    if type(value) is not list:
        raise ValueError("expected an ordered child array or native 32-byte digest")
    rows = []
    seen = set()
    for row in value:
        if type(row) is not list or len(row) != 2:
            raise ValueError("each child must contain an index and a tree")
        index, subtree = row
        if type(index) is not int or not 0 <= index <= U64_MAX or index in seen:
            raise ValueError("expected a unique unsigned 64-bit child index")
        seen.add(index)
        rows.append((index, decode_tree(subtree)))
    return Branch(tuple(rows))


def unique_fields(entries):
    fields = dict(entries)
    if len(fields) != len(entries):
        raise ValueError("duplicate field in export row")
    return fields


def read_record(path, expected_sha, height):
    if not SHA256.fullmatch(expected_sha):
        raise ValueError("expected a lowercase SHA-256 for the raw input")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_sha:
        raise ValueError(f"artifact digest mismatch: {path}")
    if len(data.splitlines()) != 1:
        raise ValueError("provide exactly one selected native export line")
    row = json.loads(data, object_pairs_hook=unique_fields)
    if type(row) is not dict or set(row) != FIELDS:
        raise ValueError("expected the three-field native abci_hashes row")
    if type(row["height"]) is not int or row["height"] != height:
        raise ValueError("row height differs from the requested height")
    if type(row["abci_digest"]) is not str or not DIGEST.fullmatch(row["abci_digest"]):
        raise ValueError("invalid raw abci_digest")
    return row["abci_digest"], decode_tree(row["exchange_abci_hash"])


def first_difference(left, right, path=()):
    if type(left) is not type(right):
        return {"path": path, "kind": "leaf_vs_branch"}
    if isinstance(left, Leaf):
        return None if left == right else {"path": path, "kind": "leaf_digest"}

    for ordinal, ((li, lv), (ri, rv)) in enumerate(zip(left.rows, right.rows)):
        if li != ri:
            left_indices = {i for i, _ in left.rows}
            right_indices = {i for i, _ in right.rows}
            return {
                "path": path, "kind": "child_order" if left_indices == right_indices else "child_index",
                "ordinal": ordinal, "reference_index": li, "observation_index": ri,
            }
        difference = first_difference(lv, rv, (*path, li))
        if difference is not None:
            return difference
    if len(left.rows) != len(right.rows):
        return {
            "path": path, "kind": "child_count", "reference_count": len(left.rows),
            "observation_count": len(right.rows),
        }
    return None


def compare(reference, reference_sha, observation, observation_sha, height):
    if type(height) is not int or not 0 <= height <= U64_MAX:
        raise ValueError("height must be an unsigned 64-bit integer")
    reference_root, reference_tree = read_record(reference, reference_sha, height)
    observation_root, observation_tree = read_record(observation, observation_sha, height)
    return {
        "height": height,
        "raw_digest_equal": reference_root == observation_root,
        "first_tree_difference": first_difference(reference_tree, observation_tree),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("height", type=int)
    parser.add_argument("reference", type=Path)
    parser.add_argument("reference_sha256")
    parser.add_argument("observation", type=Path)
    parser.add_argument("observation_sha256")
    args = parser.parse_args()
    try:
        result = compare(args.reference, args.reference_sha256, args.observation,
                         args.observation_sha256, args.height)
    except (OSError, ValueError, RecursionError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["raw_digest_equal"] and result["first_tree_difference"] is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
