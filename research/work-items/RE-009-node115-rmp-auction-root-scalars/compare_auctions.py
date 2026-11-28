"""Compare supported gas-auction branches in a named #115 checkpoint and raw root export."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from types import ModuleType

SLOTS = {
    "register_token_gas_auction": 28,
    "perp_deploy_gas_auction": 29,
    "spot_pair_deploy_gas_auction": 30,
}
SCALARS = {
    "bucket_guard.last_bucket": (0, 0, 0),
    "bucket_guard.bucket_millis": (0, 0, 1),
    "start_gas_wei": (0, 1, 0),
    "token": (0, 3),
    "initial_gas_to_last_auction_gas_ratio": (0, 4),
    "min_gas": (0, 5, 0),
}
DEPENDENCIES = {
    "rmp": ("RE-009-node115-msgpack-context-projection/project.py",
            "77b38608aca44aac753c6440038b5baf2646474846aaba911794ed99f84be3cf"),
    "tree": ("RE-009-node115-context-root-isolation/isolate.py",
             "acb3c71a3c56b42d9614aeb78225cfc90f364e8468db144c0f55e22a175fc3ec"),
}


def load_helpers(folder):
    modules = {}
    for name, (relative, sha256) in DEPENDENCIES.items():
        path = folder / relative
        source = path.read_bytes()
        if hashlib.sha256(source).hexdigest() != sha256:
            raise ValueError(f"source pin mismatch for {relative}")
        module = ModuleType(f"node115_auction_{name}")
        exec(compile(source, str(path), "exec"), module.__dict__)
        modules[name] = module
    return modules


def read_checkpoint(rmp, path, pin, height):
    import msgpack

    def exchange(unpacker):
        return rmp.select(unpacker, {**dict.fromkeys(SLOTS, rmp.read_value), "locus": lambda u: rmp.require(
            u, "ctx", lambda ctx: rmp.require(ctx, "height", rmp.read_value)
        )})

    with path.open("rb") as stream:
        reader = rmp.HashingReader(stream)
        unpacker = msgpack.Unpacker(reader, raw=False, object_pairs_hook=unique_fields)
        try:
            fields = rmp.require(unpacker, "exchange", exchange)
        except msgpack.OutOfData as error:
            raise ValueError("incomplete named checkpoint object") from error
        position = unpacker.tell()
        while reader.read(65536):
            pass
        if reader.digest.hexdigest() != pin:
            raise ValueError("checkpoint SHA-256 mismatch")
        if position != reader.count:
            raise ValueError("trailing bytes after checkpoint object")
    if type(fields.get("locus")) is not int or fields["locus"] != height:
        raise ValueError("checkpoint Context height mismatch")
    for name in SLOTS:
        if name not in fields:
            raise ValueError(f"checkpoint omits {name}")
    return fields


def unique_fields(pairs):
    values = dict(pairs)
    if len(values) != len(pairs):
        raise ValueError("duplicate field in an auction payload")
    return values


def unsigned_qword(value, field):
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError(f"expected unsigned 64-bit {field}")
    return value.to_bytes(8, "little")


def checkpoint_preimages(auction):
    if auction is None:
        return {"presence": bytes(8)}
    if type(auction) is not dict or type(auction.get("bucket_guard")) is not dict:
        raise ValueError("expected named auction and bucket_guard maps")
    values = {**auction, **{"bucket_guard." + name: value
                           for name, value in auction["bucket_guard"].items()}}
    return {"presence": b"\x01" + bytes(7),
            **{field: unsigned_qword(values.get(field), field) for field in SCALARS}}


def descend(tree, path):
    for index in path:
        if type(tree) is not tuple:
            return None
        tree = dict(tree).get(index)
    return tree


def compare(helpers, executable, height, checkpoint, checkpoint_pin, reference, reference_pin):
    unsigned_qword(height, "checkpoint height")
    fields = read_checkpoint(helpers["rmp"], checkpoint, checkpoint_pin, height)
    tree = helpers["tree"]
    stated, parsed = tree.read_export(reference, reference_pin, height)
    if tree.digest(executable, parsed) != stated:
        raise ValueError("reference tree does not reproduce its stated raw ABCI digest")

    def hash_leaf(raw):
        result = subprocess.run([executable.resolve()], input=raw, check=True, capture_output=True)
        digest = result.stdout.decode("ascii").strip()
        if not tree.DIGEST.fullmatch(digest):
            raise ValueError("local helper returned an invalid digest")
        return bytes.fromhex(digest[2:])

    results = {}
    for name, slot in SLOTS.items():
        present = fields[name] is not None
        branch = descend(parsed, (slot,))
        paths = {"presence": (1,), **SCALARS}
        comparisons = {field: descend(branch, paths[field]) == hash_leaf(raw)
                       for field, raw in checkpoint_preimages(fields[name]).items()}
        children = (0, 1) if present else (1,)
        shape = type(branch) is tuple and tuple(key for key, _ in branch) == children
        results[name] = {"slot": slot, "ordered_wrapper_matches": shape, "leaves": comparisons}
    return {"height": height, "reference_raw_digest": stated, "auctions": results,
            "selected_checks_pass": all(check["ordered_wrapper_matches"] and all(check["leaves"].values())
                                        for check in results.values())}


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
        result = compare(load_helpers(args.helpers), args.hash_helper, args.height, args.checkpoint,
                         args.checkpoint_sha256, args.reference, args.reference_sha256)
    except (ValueError, OSError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["selected_checks_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
