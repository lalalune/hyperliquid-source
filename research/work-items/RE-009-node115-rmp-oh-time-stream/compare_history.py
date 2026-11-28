"""Compare the #115 Oracle-history ordered checkpoint Time stream with raw ABCI."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from types import ModuleType

SLOT = 52
DEPENDENCIES = {
    "rmp": ("RE-009-node115-msgpack-context-projection/project.py",
            "77b38608aca44aac753c6440038b5baf2646474846aaba911794ed99f84be3cf"),
    "normalize": ("RE-009-node115-checkpoint-context-projection/project.py",
                  "5b8f909500007bc23aa6ce46d0d9abf79fab081e6a35a68587d07edec95bbebd"),
    "clock": ("RE-009-node115-context-subtree-compare/compare.py",
              "9fe1de5c63e742c1974b8ecb2888e7acaca80d95a599d54178bc7f38edf15241"),
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
        module = ModuleType(f"node115_exchange_{name}")
        exec(compile(source, str(path), "exec"), module.__dict__)
        modules[name] = module
    return modules


def read_history(kit, path, pin, height):
    import msgpack

    rmp = kit["rmp"]

    def history(unpacker):
        count = unpacker.read_array_header()
        if count == 0:
            raise ValueError("expected a nonempty Exchange.oh sequence")
        times = bytearray()
        for index in range(count):
            if unpacker.read_array_header() != 2:
                raise ValueError(f"expected an Exchange.oh pair at row {index}")
            timestamp = unpacker.unpack()
            unpacker.skip()
            if type(timestamp) is not str or not timestamp[:4].isdigit() or int(timestamp[:4]) == 0:
                raise ValueError(f"expected a positive-year Time at row {index}")
            try:
                times.extend(kit["clock"].clock(kit["normalize"].clock(timestamp)))
            except ValueError as error:
                raise ValueError(f"Exchange.oh row {index}: {error}") from error
        return count, times

    def exchange(unpacker):
        return rmp.select(unpacker, {
            "oh": history,
            "locus": lambda u: rmp.require(u, "ctx", lambda ctx: rmp.require(ctx, "height", rmp.read_value)),
        })

    with path.open("rb") as stream:
        data = rmp.HashingReader(stream)
        unpacker = msgpack.Unpacker(data, raw=False)
        try:
            fields = rmp.require(unpacker, "exchange", exchange)
        except msgpack.OutOfData as error:
            raise ValueError("incomplete named checkpoint object") from error
        consumed = unpacker.tell()
        while data.read(65536):
            pass
        if data.digest.hexdigest() != pin:
            raise ValueError("checkpoint SHA-256 mismatch")
        if consumed != data.count:
            raise ValueError("trailing bytes after checkpoint object")
    if type(fields.get("locus")) is not int or fields["locus"] != height:
        raise ValueError("checkpoint Context height mismatch")
    if "oh" not in fields:
        raise ValueError("checkpoint omits Exchange.oh")
    return fields["oh"]


def compare(kit, helper, height, checkpoint, checkpoint_pin, reference, reference_pin):
    if type(height) is not int or not 0 <= height < 1 << 64:
        raise ValueError("expected unsigned 64-bit checkpoint height")
    count, raw_times = read_history(kit, checkpoint, checkpoint_pin, height)
    tree = kit["tree"]
    digest, ordered = tree.read_export(reference, reference_pin, height)
    if tree.digest(helper, ordered) != digest:
        raise ValueError("reference tree does not reproduce its stated raw ABCI digest")
    if type(ordered) is not tuple:
        raise ValueError("expected raw Exchange branch")

    def leaf(raw):
        output = subprocess.run([helper.resolve()], input=raw, check=True, capture_output=True)
        hex_digest = output.stdout.decode("ascii").strip()
        if not tree.DIGEST.fullmatch(hex_digest):
            raise ValueError("local helper returned an invalid digest")
        return bytes.fromhex(hex_digest[2:])

    branch = dict(ordered).get(SLOT)
    children = dict(branch) if type(branch) is tuple else {}
    row_stream = children.get(0)
    streams = dict(row_stream) if type(row_stream) is tuple else {}
    shape = (type(branch) is tuple and tuple(children) == (0, 1)
             and type(row_stream) is tuple and tuple(streams) == (0, 1))
    timestamp_match = streams.get(0) == leaf(raw_times)
    count_match = children.get(1) == leaf(count.to_bytes(8, "little"))
    return {"height": height, "reference_raw_digest": digest, "row_count": count,
            "projection_shape_matches": shape, "ordered_time_stream_matches": timestamp_match,
            "row_count_matches": count_match, "scoped_match": shape and timestamp_match and count_match}


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
