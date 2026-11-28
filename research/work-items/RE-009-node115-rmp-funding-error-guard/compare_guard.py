"""Compare the named #115 funding error duration guard with its full raw subtree."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import struct
import subprocess
from types import ModuleType

GUARD = "funding_err_dur_guard"
KEYS = ("err_duration", "first_err_time", "last_err_time")
SLOT = 11
DEPENDENCIES = {
    "rmp": ("RE-009-node115-msgpack-context-projection/project.py",
            "77b38608aca44aac753c6440038b5baf2646474846aaba911794ed99f84be3cf"),
    "normalize": ("RE-009-node115-checkpoint-context-projection/project.py",
                  "5b8f909500007bc23aa6ce46d0d9abf79fab081e6a35a68587d07edec95bbebd"),
    "preimage": ("RE-009-node115-context-subtree-compare/compare.py",
                 "9fe1de5c63e742c1974b8ecb2888e7acaca80d95a599d54178bc7f38edf15241"),
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
        module = ModuleType(f"node115_funding_{name}")
        exec(compile(source, str(path), "exec"), module.__dict__)
        modules[name] = module
    return modules


def read_guard(rmp, path, pin, height):
    import msgpack

    def duration(unpacker):
        start = unpacker.tell()
        value = unpacker.unpack()
        if type(value) is not float or unpacker.tell() - start != 9 or not math.isfinite(value):
            raise ValueError("expected finite MessagePack binary64 err_duration")
        return value

    def exchange(u):
        return rmp.select(u, {
            GUARD: lambda g: rmp.select(g, {**dict.fromkeys(KEYS, rmp.read_value), KEYS[0]: duration}),
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
    guard = fields.get(GUARD, {})
    if set(guard) != set(KEYS):
        raise ValueError("expected all three named funding guard fields")
    return guard


def compare(kit, helper, height, checkpoint, checkpoint_sha, reference, reference_sha):
    if type(height) is not int or not 0 <= height < 1 << 64:
        raise ValueError("expected unsigned 64-bit checkpoint height")
    guard = read_guard(kit["rmp"], checkpoint, checkpoint_sha, height)
    tree = kit["tree"]
    digest, ordered = tree.read_export(reference, reference_sha, height)
    if tree.digest(helper, ordered) != digest:
        raise ValueError("reference tree does not reproduce its stated raw ABCI digest")
    if type(ordered) is not tuple:
        raise ValueError("expected raw Exchange branch")

    def leaf(raw):
        result = subprocess.run([helper.resolve()], input=raw, check=True, capture_output=True)
        value = result.stdout.decode("ascii").strip()
        if not tree.DIGEST.fullmatch(value):
            raise ValueError("local helper returned an invalid digest")
        return bytes.fromhex(value[2:])

    def time_option(text):
        if text is None:
            return ((1, leaf(bytes(8))),)
        packed = kit["preimage"].clock(kit["normalize"].clock(text))
        return ((0, leaf(packed)), (1, leaf(b"\x01" + bytes(7))))

    expected = ((0, leaf(struct.pack("<d", guard[KEYS[0]]))),
                (1, time_option(guard[KEYS[1]])),
                (2, time_option(guard[KEYS[2]])))
    actual = dict(ordered).get(SLOT)
    values = dict(actual) if type(actual) is tuple else {}
    return {"height": height, "slot": SLOT, "reference_raw_digest": digest,
            "ordered_guard_subtree_matches": expected == actual,
            "fields": {KEYS[index]: values.get(index) == shape for index, shape in expected}}


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
    return 0 if output["ordered_guard_subtree_matches"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
