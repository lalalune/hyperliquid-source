"""Measure whether Context accounts for a same-height raw ABCI root difference."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from abci_hash_tree_encoding_115 import enc_array_len, enc_leaf, enc_uint

DIGEST = re.compile(r"0x[0-9a-f]{64}")
U64_MAX = (1 << 64) - 1
CONTEXT_PATH = (0, 0)


def decode_tree(data):
    if type(data) is str and DIGEST.fullmatch(data):
        return bytes.fromhex(data[2:])
    if type(data) is not list:
        raise ValueError("expected a native ordered branch or 32-byte digest leaf")
    result = []
    seen = set()
    for entry in data:
        if type(entry) is not list or len(entry) != 2:
            raise ValueError("expected a two-element child row")
        index, child = entry
        if type(index) is not int or not 0 <= index <= U64_MAX or index in seen:
            raise ValueError("invalid or duplicate tree index")
        seen.add(index)
        result.append((index, decode_tree(child)))
    return tuple(result)


def unique_fields(pairs):
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("duplicate field in export")
    return fields


def read_export(path, expected_sha, height):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_sha:
        raise ValueError(f"export SHA-256 mismatch for {path}")
    row = json.loads(data, object_pairs_hook=unique_fields)
    if type(row) is not dict or set(row) != {"height", "abci_digest", "exchange_abci_hash"}:
        raise ValueError("expected a native three-field abci_hashes row")
    if type(row["height"]) is not int or row["height"] != height:
        raise ValueError("export height differs from requested height")
    digest = row["abci_digest"]
    if type(digest) is not str or not DIGEST.fullmatch(digest):
        raise ValueError("invalid native raw ABCI digest")
    return digest, decode_tree(row["exchange_abci_hash"])


def at_path(tree, path):
    for index in path:
        if type(tree) is not tuple:
            raise ValueError("Context path reaches a leaf before [0,0]")
        children = dict(tree)
        if index not in children:
            raise ValueError("missing native Context path [0,0]")
        tree = children[index]
    if type(tree) is not tuple:
        raise ValueError("native Context must be an ordered branch")
    return tree


def substitute(tree, path, new):
    if not path:
        return new
    index, *remainder = path
    return tuple((key, substitute(child, remainder, new) if key == index else child)
                 for key, child in tree)


def append_preimage(tree, output):
    if type(tree) is bytes:
        output.extend(enc_leaf(tree))
        return
    output.extend(enc_array_len(len(tree)))
    for index, child in tree:
        output.extend(enc_array_len(2))
        output.extend(enc_uint(index))
        append_preimage(child, output)


def digest(helper, tree):
    payload = bytearray()
    append_preimage(tree, payload)
    output = subprocess.run([helper.resolve()], input=payload, check=True, capture_output=True)
    text = output.stdout.decode("ascii").strip()
    if not DIGEST.fullmatch(text):
        raise ValueError("local BLAKE3 helper returned an invalid digest")
    return text


def isolate(helper, height, reference, reference_sha, observed, observed_sha):
    if type(height) is not int or not 0 <= height <= U64_MAX:
        raise ValueError("height must be a u64")
    reference_root, reference_tree = read_export(reference, reference_sha, height)
    observed_root, observed_tree = read_export(observed, observed_sha, height)
    for label, stated, tree in (("reference", reference_root, reference_tree),
                                ("observed", observed_root, observed_tree)):
        if digest(helper, tree) != stated:
            raise ValueError(f"{label} tree does not reproduce its own raw digest")
    original = at_path(reference_tree, CONTEXT_PATH)
    replacement = at_path(observed_tree, CONTEXT_PATH)
    isolated_tree = substitute(reference_tree, CONTEXT_PATH, replacement)
    isolated_root = digest(helper, isolated_tree)
    return {
        "height": height,
        "context_changed": original != replacement,
        "outside_context_equal": isolated_tree == observed_tree,
        "reference_raw_digest": reference_root,
        "observed_raw_digest": observed_root,
        "reference_with_observed_context_digest": isolated_root,
        "substitution_matches_observed_digest": isolated_root == observed_root,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("helper", type=Path)
    parser.add_argument("height", type=int)
    parser.add_argument("reference", type=Path)
    parser.add_argument("reference_sha256")
    parser.add_argument("observed", type=Path)
    parser.add_argument("observed_sha256")
    args = parser.parse_args()
    try:
        output = isolate(args.helper, args.height, args.reference, args.reference_sha256,
                         args.observed, args.observed_sha256)
    except (ValueError, OSError, subprocess.SubprocessError, RecursionError) as error:
        parser.error(str(error))
    print(json.dumps(output, sort_keys=True))
    return 0 if output["outside_context_equal"] and output["substitution_matches_observed_digest"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
