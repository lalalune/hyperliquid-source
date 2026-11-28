"""Compare six direct Exchange leaves from a named checkpoint and raw export."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from types import ModuleType

FIELDS = {
    "spot_disabled": (23, bool),
    "prune_agent_idx": (24, int),
    "evm_enabled": (38, bool),
    "hip3_no_cross": (46, bool),
    "dex_abstraction_enabled": (50, bool),
    "pmn": (55, int),
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
        module = ModuleType(f"node115_direct_{name}")
        exec(compile(source, str(path), "exec"), module.__dict__)
        modules[name] = module
    return modules


def read_named_fields(rmp, path, pin, height):
    import msgpack

    def exchange(unpacker):
        return rmp.select(unpacker, {**dict.fromkeys(FIELDS, rmp.read_value), "locus": lambda u: rmp.require(
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
    raw = {}
    for name, (slot, kind) in FIELDS.items():
        if name not in fields:
            raise ValueError(f"checkpoint omits {name}")
        value = fields[name]
        if type(value) is not kind or (kind is int and not 0 <= value < 1 << 64):
            raise ValueError(f"expected native {kind.__name__} value for {name}")
        raw[slot] = int(value).to_bytes(1 if kind is bool else 8, "little")
    return raw


def compare(helpers, executable, height, checkpoint, checkpoint_pin, reference, reference_pin):
    if type(height) is not int or not 0 <= height < 1 << 64:
        raise ValueError("expected unsigned 64-bit checkpoint height")
    source = read_named_fields(helpers["rmp"], checkpoint, checkpoint_pin, height)
    tree = helpers["tree"]
    stated, ordered = tree.read_export(reference, reference_pin, height)
    if tree.digest(executable, ordered) != stated:
        raise ValueError("reference tree does not reproduce its stated raw ABCI digest")
    if type(ordered) is not tuple:
        raise ValueError("expected ordered raw exchange ABCI branch")
    actual = dict(ordered)
    projected = {}
    for slot, raw in source.items():
        result = subprocess.run([executable.resolve()], input=raw, check=True, capture_output=True)
        digest = result.stdout.decode("ascii").strip()
        if not tree.DIGEST.fullmatch(digest):
            raise ValueError("local helper returned an invalid digest")
        projected[slot] = bytes.fromhex(digest[2:])
    checks = {name: {"slot": slot, "matches": actual.get(slot) == projected[slot]}
              for name, (slot, _) in FIELDS.items()}
    return {"height": height, "reference_raw_digest": stated, "fields": checks,
            "all_direct_leaves_match": all(row["matches"] for row in checks.values())}


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
    return 0 if result["all_direct_leaves_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
