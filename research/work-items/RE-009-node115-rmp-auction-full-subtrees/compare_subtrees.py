"""Compare complete checkpoint gas-auction subtrees with a same-height raw export."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from types import ModuleType

SCALARS = "RE-009-node115-rmp-auction-root-scalars/compare_auctions.py"
SCALARS_SHA = "26ca3e0c87474beb5b3bf0eb8be7c70ab8f1aedc01800739541e231f09bf6397"


def load_scalars(folder):
    path = folder / SCALARS
    source = path.read_bytes()
    if hashlib.sha256(source).hexdigest() != SCALARS_SHA:
        raise ValueError("expected pinned #7505 scalar/checkpoint helper")
    module = ModuleType("node115_auction_scalars")
    exec(compile(source, str(path), "exec"), module.__dict__)
    return module


def build_subtree(scalars, hasher, auction):
    raw = scalars.checkpoint_preimages(auction)
    presence = (1, hasher(raw["presence"]))
    if auction is None:
        return (presence,)

    def quantity(qword):
        return ((0, hasher(qword)), (1, hasher(b"")))

    if "end_gas_wei" not in auction:
        raise ValueError("checkpoint omits end_gas_wei inside a present auction")
    end = auction["end_gas_wei"]
    if end is None:
        optional_end = ((1, hasher(bytes(8))),)
    else:
        optional_end = ((0, quantity(scalars.unsigned_qword(end, "end_gas_wei"))),
                        (1, hasher(b"\x01" + bytes(7))))
    payload = (
        (0, ((0, hasher(raw["bucket_guard.last_bucket"])),
             (1, hasher(raw["bucket_guard.bucket_millis"])))),
        (1, quantity(raw["start_gas_wei"])),
        (2, optional_end),
        (3, hasher(raw["token"])),
        (4, hasher(raw["initial_gas_to_last_auction_gas_ratio"])),
        (5, quantity(raw["min_gas"])),
    )
    return ((0, payload), presence)


def first_mismatch(expected, actual, path):
    if expected == actual:
        return None
    if type(expected) is tuple and type(actual) is tuple:
        actual_children = dict(actual)
        if tuple(index for index, _ in expected) == tuple(actual_children):
            for index, child in expected:
                mismatch = first_mismatch(child, actual_children[index], (*path, index))
                if mismatch is not None:
                    return mismatch
    return path


def compare(scalars, kit, helper, height, checkpoint, checkpoint_sha, reference, reference_sha):
    scalars.unsigned_qword(height, "checkpoint height")
    native_fields = scalars.read_checkpoint(kit["rmp"], checkpoint, checkpoint_sha, height)
    tree = kit["tree"]
    stated, original = tree.read_export(reference, reference_sha, height)
    if tree.digest(helper, original) != stated:
        raise ValueError("reference tree does not reproduce its stated raw ABCI digest")
    if type(original) is not tuple:
        raise ValueError("expected native exchange branch")

    hashes = {}

    def hash_leaf(raw):
        if raw not in hashes:
            result = subprocess.run([helper.resolve()], input=raw, check=True, capture_output=True)
            digest = result.stdout.decode("ascii").strip()
            if not tree.DIGEST.fullmatch(digest):
                raise ValueError("local helper returned an invalid digest")
            hashes[raw] = bytes.fromhex(digest[2:])
        return hashes[raw]

    original_slots = dict(original)
    replacements = {}
    differences = {}
    for name, slot in scalars.SLOTS.items():
        if slot not in original_slots:
            raise ValueError(f"reference omits ordered exchange slot {slot}")
        expected = build_subtree(scalars, hash_leaf, native_fields[name])
        replacements[slot] = expected
        differences[name] = first_mismatch(expected, original_slots[slot], (slot,))
    isolated = tuple((slot, replacements.get(slot, value)) for slot, value in original)
    return {
        "height": height,
        "reference_raw_digest": stated,
        "reference_with_projected_auctions_digest": tree.digest(helper, isolated),
        "all_auction_subtrees_match": original == isolated,
        "first_different_paths": differences,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("helpers", type=Path)
    parser.add_argument("hash_helper", type=Path)
    parser.add_argument("height", type=int)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("checkpoint_sha256")
    parser.add_argument("reference", type=Path)
    parser.add_argument("reference_sha256")
    args = parser.parse_args()
    try:
        scalar_module = load_scalars(args.helpers)
        result = compare(scalar_module, scalar_module.load_helpers(args.helpers), args.hash_helper,
                         args.height, args.checkpoint, args.checkpoint_sha256,
                         args.reference, args.reference_sha256)
    except (ValueError, OSError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["all_auction_subtrees_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
