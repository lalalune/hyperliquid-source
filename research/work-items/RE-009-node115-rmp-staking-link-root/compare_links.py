"""Compare the persisted #115 staking links with their complete ordered ABCI subtree."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from types import ModuleType

FIELD = "staking_link_tracker"
LINKS = "user_to_staking_link2"
SLOT = 40
ADDRESS = re.compile(r"0x[0-9a-f]{40}")
VARIANTS = {"Requested": (0, "staking_user"), "TradingUser": (1, "staking_user"),
            "StakingUser": (2, "trading_user")}
DEPENDENCIES = {
    "rmp": ("RE-009-node115-msgpack-context-projection/project.py",
            "77b38608aca44aac753c6440038b5baf2646474846aaba911794ed99f84be3cf"),
    "tree": ("RE-009-node115-context-root-isolation/isolate.py",
             "acb3c71a3c56b42d9614aeb78225cfc90f364e8468db144c0f55e22a175fc3ec"),
}


def load_helpers(folder):
    modules = {}
    for name, (relative, pin) in DEPENDENCIES.items():
        path = folder / relative
        source = path.read_bytes()
        if hashlib.sha256(source).hexdigest() != pin:
            raise ValueError(f"source pin mismatch for {relative}")
        module = ModuleType(f"node115_staking_links_{name}")
        exec(compile(source, str(path), "exec"), module.__dict__)
        modules[name] = module
    return modules


def address(value):
    if type(value) is not str or not ADDRESS.fullmatch(value):
        raise ValueError("expected writer-shaped 20-byte Address")
    return bytes.fromhex(value[2:])


def read_rows(unpacker):
    count = unpacker.read_array_header()
    keys, types = bytearray(), bytearray()
    payloads = [bytearray() for _ in VARIANTS]
    seen = set()
    for _ in range(count):
        if unpacker.read_array_header() != 2:
            raise ValueError("expected key and variant in every staking-link pair")
        key = address(unpacker.unpack())
        if key in seen:
            raise ValueError("duplicate staking-link Address")
        seen.add(key)
        keys.extend(key)
        if unpacker.read_map_header() != 1:
            raise ValueError("expected a single named staking-link variant")
        name = unpacker.unpack()
        if type(name) is not str or name not in VARIANTS:
            raise ValueError("unknown named staking-link variant")
        tag, target = VARIANTS[name]
        if unpacker.read_map_header() != 1 or unpacker.unpack() != target:
            raise ValueError("staking-link variant payload key differs from writer shape")
        payloads[tag].extend(address(unpacker.unpack()))
        types.extend(tag.to_bytes(8, "little"))
    return count, keys, payloads, types


def read_checkpoint(rmp, path, sha, height):
    import msgpack

    def exchange(u):
        return rmp.select(u, {
            FIELD: lambda tracker: rmp.require(tracker, LINKS, read_rows),
            "locus": lambda loc: rmp.require(loc, "ctx", lambda ctx: rmp.require(ctx, "height", rmp.read_value)),
        })

    with path.open("rb") as stream:
        reader = rmp.HashingReader(stream)
        unpacker = msgpack.Unpacker(reader, raw=False)
        try:
            fields = rmp.require(unpacker, "exchange", exchange)
        except msgpack.OutOfData as error:
            raise ValueError("incomplete named checkpoint object") from error
        consumed = unpacker.tell()
        while reader.read(65536):
            pass
        if reader.digest.hexdigest() != sha:
            raise ValueError("checkpoint SHA-256 mismatch")
        if consumed != reader.count:
            raise ValueError("trailing bytes after checkpoint object")
    if type(fields.get("locus")) is not int or fields["locus"] != height:
        raise ValueError("checkpoint Context height mismatch")
    if FIELD not in fields:
        raise ValueError(f"checkpoint omits {FIELD}")
    return fields[FIELD]


def compare(kit, helper, height, checkpoint, checkpoint_pin, reference, reference_pin):
    if type(height) is not int or not 0 <= height < 1 << 64:
        raise ValueError("expected unsigned 64-bit checkpoint height")
    count, keys, payloads, tags = read_checkpoint(kit["rmp"], checkpoint, checkpoint_pin, height)
    tree = kit["tree"]
    stated, ordered = tree.read_export(reference, reference_pin, height)
    if tree.digest(helper, ordered) != stated:
        raise ValueError("reference tree does not reproduce its stated raw ABCI digest")
    if type(ordered) is not tuple:
        raise ValueError("expected ordered raw Exchange branch")

    def leaf(raw):
        output = subprocess.run([helper.resolve()], input=raw, check=True, capture_output=True)
        value = output.stdout.decode("ascii").strip()
        if not tree.DIGEST.fullmatch(value):
            raise ValueError("local helper returned an invalid digest")
        return bytes.fromhex(value[2:])

    expected_map = ()
    if count:
        variants = tuple((idx, leaf(payload)) for idx, payload in enumerate(payloads) if payload)
        expected_map = ((0, leaf(keys)), (1, variants + ((3, leaf(tags)),)))
    expected_map += ((2, leaf(count.to_bytes(8, "little"))),)
    actual = dict(ordered).get(SLOT)
    stored_map = dict(actual).get(0) if type(actual) is tuple else None
    expected_items = dict(expected_map)
    actual_items = dict(stored_map) if type(stored_map) is tuple else {}
    return {"height": height, "reference_raw_digest": stated, "slot": SLOT, "entry_count": count,
            "ordered_subtree_matches": actual == ((0, expected_map),),
            "key_stream_matches": expected_items.get(0) == actual_items.get(0),
            "variant_subtree_matches": expected_items.get(1) == actual_items.get(1),
            "count_leaf_matches": expected_items[2] == actual_items.get(2)}


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
        output = compare(load_helpers(args.helpers), args.hash_helper, args.height, args.checkpoint,
                         args.checkpoint_sha256, args.reference, args.reference_sha256)
    except (ValueError, OSError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print(json.dumps(output, sort_keys=True))
    return 0 if output["ordered_subtree_matches"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
