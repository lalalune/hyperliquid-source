"""Compare the complete named #115 Locus ctr.ac subtree against raw ABCI."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from types import ModuleType

DIRECT = ("p", "m", "l", "L")
FIVE_WORDS = ("t", "s", "c", "u", "l")
GROUPS = ("M", "b", "c")
CLOCKS = ("s", "t")
EPOCH = "1970-01-01T00:00:00"
DEPENDENCIES = {
    "normalize": ("RE-009-node115-checkpoint-context-projection/project.py",
                  "5b8f909500007bc23aa6ce46d0d9abf79fab081e6a35a68587d07edec95bbebd"),
    "clock": ("RE-009-node115-context-subtree-compare/compare.py",
              "9fe1de5c63e742c1974b8ecb2888e7acaca80d95a599d54178bc7f38edf15241"),
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
        module = ModuleType(f"node115_locus_ctr_ac_{name}")
        exec(compile(source, str(path), "exec"), module.__dict__)
        modules[name] = module
    return modules


def word(value, label):
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError(f"expected unsigned 64-bit {label}")
    return value.to_bytes(8, "little")


def read_checkpoint(kit, path, pin, height):
    import msgpack

    rmp = kit["rmp"]

    def read_group(unpacker, keys):
        return rmp.select(unpacker, dict.fromkeys(keys, rmp.read_value))

    def activity(unpacker):
        return rmp.select(unpacker, {
            **dict.fromkeys(DIRECT, rmp.read_value),
            **dict.fromkeys(GROUPS, lambda u: read_group(u, FIVE_WORDS)),
            **dict.fromkeys(CLOCKS, lambda u: read_group(u, ("n", "t"))),
        })

    def locus(u):
        return rmp.select(u, {
            "ctr": lambda counters: rmp.select(counters, {"ac": activity}),
            "ctx": lambda ctx: rmp.require(ctx, "height", rmp.read_value),
        })

    def exchange(u):
        return rmp.require(u, "locus", locus)

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
    if type(fields.get("ctx")) is not int or fields["ctx"] != height:
        raise ValueError("checkpoint Context height mismatch")
    if "ctr" not in fields:
        raise ValueError("checkpoint omits Locus ctr")
    values = fields["ctr"].get("ac", {})
    direct = tuple(word(values.get(key, 0), key) for key in DIRECT)
    groups = tuple(tuple(word(values.get(name, {}).get(key, 0), f"{name}.{key}") for key in FIVE_WORDS)
                   for name in GROUPS)
    clocks = []
    for name in CLOCKS:
        timed = values.get(name, {})
        count = word(timed.get("n", 0), f"{name}.n")
        clock = kit["clock"].clock(kit["normalize"].clock(timed.get("t", EPOCH)))
        clocks.append((count, clock))
    return direct, groups, clocks


def compare(kit, helper, height, checkpoint, checkpoint_pin, reference, reference_pin):
    word(height, "checkpoint height")
    direct, groups, clocks = read_checkpoint(kit, checkpoint, checkpoint_pin, height)
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

    def children(node, label):
        if type(node) is not tuple:
            raise ValueError(f"expected a raw {label} branch")
        return dict(node)

    locus = children(children(ordered, "Exchange").get(0), "Locus")
    context = children(locus.get(0), "Context")
    if context.get(2) != leaf(word(height, "reference Context height")):
        raise ValueError("reference inner Context height leaf mismatch")
    def branch(items):
        return tuple((index, leaf(raw)) for index, raw in enumerate(items))

    expected = branch(direct) + tuple((index, branch(items))
                                      for index, items in enumerate((*groups, *clocks), len(DIRECT)))
    ctr = children(locus.get(10), "Locus ctr")
    actual = ctr.get(6)
    observed = dict(actual) if type(actual) is tuple else {}
    names = DIRECT + GROUPS + CLOCKS
    matches = {name: observed.get(slot) == child for (slot, child), name in zip(expected, names)}
    return {"height": height, "reference_raw_digest": digest, "fields": matches,
            "inner_reference_height_matches": True, "ordered_activity_matches": actual == expected}


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
    return 0 if result["ordered_activity_matches"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
