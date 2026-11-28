"""Check six named Exchange BucketGuard subtrees against a pinned raw export."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from types import ModuleType

GUARDS = {
    "funding_distribute_guard": 4,
    "funding_update_guard": 5,
    "cancel_aggressive_orders_at_open_interest_cap_guard": 14,
    "book_empty_user_states_pruning_guard": 20,
    "begin_block_logic_guard": 33,
    "hip3_stale_mark_px_guard": 43,
}
BUCKET_FIELDS = ("last_bucket", "bucket_millis")
DEPENDENCIES = {
    "rmp": ("RE-009-node115-msgpack-context-projection/project.py",
            "77b38608aca44aac753c6440038b5baf2646474846aaba911794ed99f84be3cf"),
    "tree": ("RE-009-node115-context-root-isolation/isolate.py",
             "acb3c71a3c56b42d9614aeb78225cfc90f364e8468db144c0f55e22a175fc3ec"),
}


def load_helpers(folder):
    modules = {}
    for name, (relative, expected_sha) in DEPENDENCIES.items():
        path = folder / relative
        source = path.read_bytes()
        if hashlib.sha256(source).hexdigest() != expected_sha:
            raise ValueError(f"source pin mismatch for {relative}")
        module = ModuleType(f"node115_guards_{name}")
        exec(compile(source, str(path), "exec"), module.__dict__)
        modules[name] = module
    return modules


def word(value, label):
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError(f"expected unsigned 64-bit {label}")
    return value.to_bytes(8, "little")


def read_checkpoint(rmp, path, pin, height):
    import msgpack

    def bucket(unpacker):
        return rmp.select(unpacker, dict.fromkeys(BUCKET_FIELDS, rmp.read_value))

    def exchange(unpacker):
        return rmp.select(unpacker, {**dict.fromkeys(GUARDS, bucket), "locus": lambda u: rmp.require(
            u, "ctx", lambda ctx: rmp.require(ctx, "height", rmp.read_value)
        )})

    with path.open("rb") as stream:
        reader = rmp.HashingReader(stream)
        unpacker = msgpack.Unpacker(reader, raw=False)
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
    missing = set(GUARDS).difference(fields)
    if missing:
        raise ValueError(f"missing named guards: {', '.join(sorted(missing))}")
    return {name: tuple(word(fields[name].get(field), f"{name}.{field}")
                        for field in BUCKET_FIELDS) for name in GUARDS}


def compare(helpers, executable, height, checkpoint, checkpoint_pin, reference, reference_pin):
    word(height, "checkpoint height")
    decoded = read_checkpoint(helpers["rmp"], checkpoint, checkpoint_pin, height)
    tree = helpers["tree"]
    stated, ordered = tree.read_export(reference, reference_pin, height)
    if tree.digest(executable, ordered) != stated:
        raise ValueError("reference tree does not reproduce its stated raw ABCI digest")
    if type(ordered) is not tuple:
        raise ValueError("expected raw Exchange branch")
    native_slots = dict(ordered)
    hashes = {}

    def hash_leaf(raw):
        if raw not in hashes:
            output = subprocess.run([executable.resolve()], input=raw, check=True, capture_output=True)
            digest = output.stdout.decode("ascii").strip()
            if not tree.DIGEST.fullmatch(digest):
                raise ValueError("local helper returned an invalid digest")
            hashes[raw] = bytes.fromhex(digest[2:])
        return hashes[raw]

    results = {}
    for name, slot in GUARDS.items():
        expected = tuple((i, hash_leaf(raw)) for i, raw in enumerate(decoded[name]))
        native = native_slots.get(slot)
        children = dict(native) if type(native) is tuple else {}
        results[name] = {"slot": slot, "exact_subtree_match": expected == native,
                         "ordered_children_match": tuple(children) == (0, 1),
                         "fields": {field: children.get(i) == digest
                                    for (i, digest), field in zip(expected, BUCKET_FIELDS)}}
    return {"height": height, "reference_raw_digest": stated, "guards": results,
            "all_guard_subtrees_match": all(row["exact_subtree_match"] for row in results.values())}


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
    return 0 if result["all_guard_subtrees_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
