"""Compare checkpoint Context values with two subtrees in one raw #115 export."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

HEX_DIGEST = re.compile(r"0x[0-9a-f]{64}")


def unique_pairs(pairs):
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("duplicate keys in export")
    return fields


def child_rows(node):
    if type(node) is not list:
        raise ValueError("expected a tree branch")
    seen = set()
    for row in node:
        if type(row) is not list or len(row) != 2:
            raise ValueError("invalid child entry")
        index, subtree = row
        if type(index) is not int or not 0 <= index < 2 ** 64 or index in seen:
            raise ValueError("invalid or repeated child index")
        seen.add(index)
        yield index, subtree


def find_child(node, index):
    children = dict(child_rows(node))
    if index not in children:
        raise ValueError(f"missing expected tree child {index}")
    return children[index]


def leaf_rows(node):
    rows = []
    for index, value in child_rows(node):
        if type(value) is not str or not HEX_DIGEST.fullmatch(value):
            raise ValueError("invalid native digest leaf")
        rows.append([index, value])
    return rows


def compare(projection, row, height):
    if type(row) is not dict or set(row) != {"height", "abci_digest", "exchange_abci_hash"}:
        raise ValueError("expected a native three-field abci_hashes line")
    if type(row["height"]) is not int or row["height"] != height:
        raise ValueError("row height differs from requested height")
    if type(row["abci_digest"]) is not str or not HEX_DIGEST.fullmatch(row["abci_digest"]):
        raise ValueError("invalid native raw digest")
    context = find_child(find_child(row["exchange_abci_hash"], 0), 0)
    return {
        "height": height,
        "hardfork": leaf_rows(find_child(context, 1)) == projection["hardfork"],
        "tx_index": leaf_rows(find_child(context, 3)) == projection["tx_index"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("projector", type=Path)
    parser.add_argument("export_row", type=Path)
    parser.add_argument("sha256")
    parser.add_argument("height", type=int)
    parser.add_argument("hardfork_version")
    parser.add_argument("hardfork_round")
    parser.add_argument("tx_index", help="unsigned index, or 'none'")
    args = parser.parse_args()
    try:
        data = args.export_row.read_bytes()
        if hashlib.sha256(data).hexdigest() != args.sha256:
            raise ValueError("export artifact SHA-256 mismatch")
        if not 0 <= args.height < 2 ** 64:
            raise ValueError("height must be a u64")
        row = json.loads(data, object_pairs_hook=unique_pairs)
        projection = json.loads(subprocess.check_output(
            [args.projector.resolve(), args.hardfork_version, args.hardfork_round, args.tx_index],
            text=True,
        ))
        result = compare(projection, row, args.height)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["hardfork"] and result["tx_index"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
