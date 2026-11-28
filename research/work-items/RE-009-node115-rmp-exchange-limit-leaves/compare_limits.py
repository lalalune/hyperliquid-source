"""Compare two binary64 limits and two scheduling heights with a #115 raw ABCI export."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import struct
import subprocess
from types import ModuleType

FIELDS = {
    "max_order_distance_from_anchor": 12,
    "scheduled_freeze_height": 13,
    "post_only_until_height": 17,
    "max_hlp_withdraw_fraction_per_day": 25,
}
FLOATS = ("max_order_distance_from_anchor", "max_hlp_withdraw_fraction_per_day")
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
        module = ModuleType(f"node115_limit_{name}")
        exec(compile(source, str(path), "exec"), module.__dict__)
        modules[name] = module
    return modules


def read_checkpoint(rmp, path, sha, height):
    import msgpack

    def read_binary64(unpacker):
        before = unpacker.tell()
        value = unpacker.unpack()
        if type(value) is not float or unpacker.tell() - before != 9 or not math.isfinite(value):
            raise ValueError("expected finite MessagePack binary64")
        return value

    def exchange(unpacker):
        return rmp.select(unpacker, {
            **dict.fromkeys(FIELDS, rmp.read_value), **dict.fromkeys(FLOATS, read_binary64),
            "locus": lambda u: rmp.require(u, "ctx", lambda ctx: rmp.require(ctx, "height", rmp.read_value)),
        })

    with path.open("rb") as stream:
        reader = rmp.HashingReader(stream)
        unpacker = msgpack.Unpacker(reader, raw=False)
        try:
            fields = rmp.require(unpacker, "exchange", exchange)
        except msgpack.OutOfData as error:
            raise ValueError("incomplete named checkpoint object") from error
        end = unpacker.tell()
        while reader.read(65536):
            pass
        if reader.digest.hexdigest() != sha:
            raise ValueError("checkpoint SHA-256 mismatch")
        if end != reader.count:
            raise ValueError("trailing bytes after checkpoint object")
    if type(fields.get("locus")) is not int or fields["locus"] != height:
        raise ValueError("checkpoint Context height mismatch")
    missing = set(FIELDS).difference(fields)
    if missing:
        raise ValueError(f"checkpoint omits {', '.join(sorted(missing))}")
    return fields


def word(value, label):
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError(f"expected unsigned 64-bit {label}")
    return value.to_bytes(8, "little")


def compare(kit, helper, height, checkpoint, checkpoint_sha, reference, reference_sha):
    word(height, "checkpoint height")
    fields = read_checkpoint(kit["rmp"], checkpoint, checkpoint_sha, height)
    tree = kit["tree"]
    digest, ordered = tree.read_export(reference, reference_sha, height)
    if tree.digest(helper, ordered) != digest:
        raise ValueError("reference tree does not reproduce its stated raw ABCI digest")
    if type(ordered) is not tuple:
        raise ValueError("expected raw Exchange branch")
    native = dict(ordered)

    def hashed(raw):
        result = subprocess.run([helper.resolve()], input=raw, check=True, capture_output=True)
        value = result.stdout.decode("ascii").strip()
        if not tree.DIGEST.fullmatch(value):
            raise ValueError("local helper returned an invalid digest")
        return bytes.fromhex(value[2:])

    freeze = fields["scheduled_freeze_height"]
    freeze_tree = () if freeze is None else ((0, hashed(word(freeze, "scheduled_freeze_height"))),)
    freeze_tree += ((1, hashed(word(int(freeze is not None), "freeze option tag"))),)
    projected = {
        **{name: hashed(struct.pack("<d", fields[name])) for name in FLOATS},
        "scheduled_freeze_height": freeze_tree,
        "post_only_until_height": hashed(word(fields["post_only_until_height"], "post_only_until_height")),
    }
    results = {name: {"slot": slot, "matches": native.get(slot) == projected[name]}
               for name, slot in FIELDS.items()}
    return {"height": height, "reference_raw_digest": digest, "fields": results,
            "all_limit_fields_match": all(row["matches"] for row in results.values())}


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
    return 0 if result["all_limit_fields_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
