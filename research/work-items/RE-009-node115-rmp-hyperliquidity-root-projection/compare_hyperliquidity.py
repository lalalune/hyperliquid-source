"""Compare #115 Hyperliquidity range keys, row count and guard with raw ABCI."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from types import ModuleType

FIELD = "hyperliquidity"
SLOT = 22
RANGES = "spot_to_range"
GUARD = "ensure_order_bucket_guard"
GUARD_KEYS = ("last_bucket", "bucket_millis")
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
        module = ModuleType(f"node115_hyperliquidity_{name}")
        exec(compile(source, str(path), "exec"), module.__dict__)
        modules[name] = module
    return modules


def word(value, label):
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError(f"expected unsigned 64-bit {label}")
    return value.to_bytes(8, "little")


def read_checkpoint(rmp, path, pin, height):
    import msgpack

    def read_ranges(u):
        count = u.read_array_header()
        keys = bytearray()
        seen = set()
        for index in range(count):
            if u.read_array_header() != 2:
                raise ValueError(f"expected a spot range pair at row {index}")
            key = u.unpack()
            keys.extend(word(key, "spot range key"))
            if key in seen:
                raise ValueError(f"duplicate spot range key at row {index}")
            seen.add(key)
            u.skip()
        return count, keys

    def exchange(u):
        return rmp.select(u, {
            FIELD: lambda obj: rmp.select(obj, {
                RANGES: read_ranges, GUARD: lambda guard: rmp.select(guard, dict.fromkeys(GUARD_KEYS, rmp.read_value)),
            }),
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
        if reader.digest.hexdigest() != pin:
            raise ValueError("checkpoint SHA-256 mismatch")
        if consumed != reader.count:
            raise ValueError("trailing bytes after checkpoint object")
    if type(fields.get("locus")) is not int or fields["locus"] != height:
        raise ValueError("checkpoint Context height mismatch")
    values = fields.get(FIELD, {})
    if RANGES not in values or set(values.get(GUARD, {})) != set(GUARD_KEYS):
        raise ValueError("expected named spot range rows and both bucket guard fields")
    count, keys = values[RANGES]
    return count, keys, tuple(word(values[GUARD][key], key) for key in GUARD_KEYS)


def compare(kit, helper, height, checkpoint, checkpoint_pin, reference, reference_pin):
    word(height, "checkpoint height")
    count, keys, buckets = read_checkpoint(kit["rmp"], checkpoint, checkpoint_pin, height)
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

    branch = dict(ordered).get(SLOT)
    children = dict(branch) if type(branch) is tuple else {}
    ranges = children.get(0)
    streams = dict(ranges) if type(ranges) is tuple else {}
    expected_slots = (0, 1, 2) if count else (2,)
    layout = type(branch) is tuple and tuple(children) == (0, 1) and tuple(streams) == expected_slots
    key_match = streams.get(0) == (leaf(keys) if count else None)
    count_match = streams.get(2) == leaf(count.to_bytes(8, "little"))
    guard_match = children.get(1) == tuple((i, leaf(raw)) for i, raw in enumerate(buckets))
    return {"height": height, "reference_raw_digest": digest, "row_count": count,
            "projection_shape_matches": layout, "ordered_range_keys_match": key_match,
            "row_count_matches": count_match, "ensure_order_guard_matches": guard_match,
            "scoped_match": layout and key_match and count_match and guard_match}


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
    return 0 if result["scoped_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
