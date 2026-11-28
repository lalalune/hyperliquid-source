"""Compare two named Address sets with their complete #115 raw ABCI subtrees."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from types import ModuleType

SETS = {"allowed_liquidators": 7, "disabled_precompiles": 44}
ADDRESS = re.compile(r"0x[0-9a-f]{40}")
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
        module = ModuleType(f"node115_addresses_{name}")
        exec(compile(source, str(path), "exec"), module.__dict__)
        modules[name] = module
    return modules


def address_set(u):
    count = u.read_array_header()
    stream, seen = bytearray(), set()
    for _ in range(count):
        address = u.unpack()
        if type(address) is not str or not ADDRESS.fullmatch(address):
            raise ValueError("expected writer-shaped 20-byte Address in named set")
        decoded = bytes.fromhex(address[2:])
        if decoded in seen:
            raise ValueError("duplicate member in named Address set")
        seen.add(decoded)
        stream.extend(decoded)
    return count, stream


def read_checkpoint(rmp, path, sha, height):
    import msgpack

    def exchange(u):
        return rmp.select(u, {
            **dict.fromkeys(SETS, address_set),
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
    if set(SETS).difference(fields):
        raise ValueError("checkpoint is missing a named Address set")
    return fields


def compare(kit, helper, height, checkpoint, checkpoint_pin, reference, reference_pin):
    if type(height) is not int or not 0 <= height < 1 << 64:
        raise ValueError("expected unsigned 64-bit checkpoint height")
    named = read_checkpoint(kit["rmp"], checkpoint, checkpoint_pin, height)
    tree = kit["tree"]
    digest, ordered = tree.read_export(reference, reference_pin, height)
    if tree.digest(helper, ordered) != digest:
        raise ValueError("reference tree does not reproduce its stated raw ABCI digest")
    if type(ordered) is not tuple:
        raise ValueError("expected raw Exchange branch")

    def leaf(raw):
        output = subprocess.run([helper.resolve()], input=raw, check=True, capture_output=True)
        value = output.stdout.decode("ascii").strip()
        if not tree.DIGEST.fullmatch(value):
            raise ValueError("local helper returned an invalid digest")
        return bytes.fromhex(value[2:])

    native = dict(ordered)
    results = {}
    for name, slot in SETS.items():
        count, rows = named[name]
        expected = ((0, leaf(rows)),) if count else ()
        expected += ((1, leaf(count.to_bytes(8, "little"))),)
        present = native.get(slot)
        children = dict(present) if type(present) is tuple else {}
        results[name] = {"slot": slot, "entry_count": count, "ordered_subtree_matches": present == expected,
                         "address_stream_matches": children.get(0) == dict(expected).get(0),
                         "count_leaf_matches": children.get(1) == expected[-1][1]}
    return {"height": height, "reference_raw_digest": digest, "sets": results,
            "both_set_subtrees_match": all(row["ordered_subtree_matches"] for row in results.values())}


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
    return 0 if output["both_set_subtrees_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
