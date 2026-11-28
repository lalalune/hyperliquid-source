"""Reconstruct and compare the selected node #115 Context hash subtree offline."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

KEYS = (
    "hardfork_height", "hardfork", "height", "tx_index", "round", "time", "prev_time",
    "next_oid", "next_lid", "next_twap_id", "system_nonce", "use_system_nonce", "mac",
)
DIGEST = re.compile(r"0x[0-9a-f]{64}")


def require_fields(row, keys):
    if type(row) is not dict or set(row) != set(keys):
        raise ValueError(f"expected fields {', '.join(keys)}")


def integer(value, minimum, maximum, label):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label} outside supported integer range")
    return value


def word(value):
    return integer(value, 0, (1 << 64) - 1, "qword").to_bytes(8, "little")


def clock(value):
    require_fields(value, ("unix_seconds", "subsec_nanos"))
    seconds = integer(value["unix_seconds"], -62135596800, 253402300799, "Unix second")
    nanos = integer(value["subsec_nanos"], 0, 999_999_999, "nanosecond")
    return struct.pack("<qI", seconds, nanos)


def preimages(context):
    require_fields(context, KEYS)
    require_fields(context["hardfork"], ("version", "round"))
    if type(context["use_system_nonce"]) is not bool:
        raise ValueError("use_system_nonce must be boolean")
    pair = [
        [0, word(context["hardfork"]["version"])],
        [1, word(context["hardfork"]["round"])],
    ]
    tx = ([[1, word(0)]] if context["tx_index"] is None
          else [[0, word(context["tx_index"])], [1, word(1)]])
    items = (
        word(context["hardfork_height"]), pair, word(context["height"]), tx,
        word(context["round"]), clock(context["time"]), clock(context["prev_time"]),
        word(context["next_oid"]), word(context["next_lid"]), word(context["next_twap_id"]),
        word(context["system_nonce"]), bytes([context["use_system_nonce"]]), word(context["mac"]),
    )
    return [[index, value] for index, value in enumerate(items)]


def leaves(tree):
    for _, child in tree:
        if type(child) is list:
            yield from leaves(child)
        else:
            yield child


def replace_leaves(tree, digests):
    return [[index, replace_leaves(child, digests) if type(child) is list else next(digests)]
            for index, child in tree]


def project(context, hasher):
    tree = preimages(context)
    inputs = list(leaves(tree))
    result = subprocess.run(
        [hasher.resolve()], input="".join(f"{leaf.hex()}\n" for leaf in inputs),
        capture_output=True, text=True, check=True,
    )
    digests = result.stdout.splitlines()
    if len(digests) != len(inputs) or not all(DIGEST.fullmatch(value) for value in digests):
        raise ValueError("leaf helper did not return the expected digest sequence")
    return replace_leaves(tree, iter(digests))


def unique_fields(pairs):
    row = dict(pairs)
    if len(row) != len(pairs):
        raise ValueError("duplicate JSON field")
    return row


def pinned_row(path, digest):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError(f"SHA-256 mismatch for {path}")
    return json.loads(raw, object_pairs_hook=unique_fields)


def node_rows(value):
    if type(value) is not list:
        raise ValueError("expected an ordered native tree branch")
    result = {}
    for row in value:
        if type(row) is not list or len(row) != 2:
            raise ValueError("invalid native tree pair")
        index = integer(row[0], 0, (1 << 64) - 1, "tree child index")
        if index in result:
            raise ValueError("duplicate native child index")
        result[index] = row[1]
    return result


def validate_tree(value):
    if type(value) is str and DIGEST.fullmatch(value):
        return
    for child in node_rows(value).values():
        validate_tree(child)


def compare(height, context, export, hasher):
    require_fields(export, ("height", "abci_digest", "exchange_abci_hash"))
    if type(export["abci_digest"]) is not str or not DIGEST.fullmatch(export["abci_digest"]):
        raise ValueError("invalid raw digest field")
    word(height)
    if (type(context.get("height")) is not int or context["height"] != height
            or type(export["height"]) is not int or export["height"] != height):
        raise ValueError("checkpoint and export must both match the requested height")
    expected = project(context, hasher)
    found = node_rows(node_rows(export["exchange_abci_hash"])[0])[0]
    validate_tree(found)
    actual = node_rows(found)
    different = [KEYS[index] for index, child in expected if child != actual.get(index)]
    return {
        "height": height,
        "different_fields": different,
        "ordered_context_slots": list(actual) == list(range(len(KEYS))),
        "matches": expected == found,
    }


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("hasher", type=Path)
    cli.add_argument("height", type=int)
    cli.add_argument("context", type=Path)
    cli.add_argument("context_sha256")
    cli.add_argument("export", type=Path)
    cli.add_argument("export_sha256")
    args = cli.parse_args()
    try:
        context = pinned_row(args.context, args.context_sha256)
        require_fields(context, KEYS)
        export = pinned_row(args.export, args.export_sha256)
        outcome = compare(args.height, context, export, args.hasher)
    except (ValueError, OSError, KeyError, RecursionError, subprocess.SubprocessError) as error:
        cli.error(str(error))
    print(json.dumps(outcome, sort_keys=True))
    return 0 if outcome["matches"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
