"""Compare the named Locus cls count and ordered boolean stream with a raw export."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from types import ModuleType

SCALARS = "RE-009-node115-rmp-locus-scalars-root/compare_locus_scalars.py"
SCALARS_SHA = "27fa4574adbbbedd4fda037a1d606f0861f39070abd651d21c2d8de9cbd45940"
FLAG = "perform_auto_deleveraging"


def load_scalars(folder):
    path = folder / SCALARS
    source = path.read_bytes()
    if hashlib.sha256(source).hexdigest() != SCALARS_SHA:
        raise ValueError("Locus scalar helper pin mismatch")
    module = ModuleType("cls_locus_scalars")
    exec(compile(source, str(path), "exec"), module.__dict__)
    return module


def read_checkpoint(rmp, file, pin, height):
    import msgpack

    def collection(u):
        flags = bytearray()
        for _ in range(u.read_array_header()):
            flag = rmp.require(u, FLAG, rmp.read_value)
            if type(flag) is not bool:
                raise ValueError(f"expected a boolean {FLAG}")
            flags.append(flag)
        return flags

    def locus(u):
        return rmp.select(u, {"cls": collection,
                              "ctx": lambda ctx: rmp.require(ctx, "height", rmp.read_value)})

    def exchange(u):
        return rmp.require(u, "locus", locus)

    with file.open("rb") as source:
        reader = rmp.HashingReader(source)
        unpacker = msgpack.Unpacker(reader, raw=False)
        try:
            selected = rmp.require(unpacker, "exchange", exchange)
        except msgpack.OutOfData as error:
            raise ValueError("incomplete named checkpoint object") from error
        consumed = unpacker.tell()
        while reader.read(65536):
            pass
        if reader.digest.hexdigest() != pin:
            raise ValueError("checkpoint SHA-256 mismatch")
        if consumed != reader.count:
            raise ValueError("trailing bytes after checkpoint object")
    if type(selected.get("ctx")) is not int or selected["ctx"] != height:
        raise ValueError("checkpoint Context height mismatch")
    if "cls" not in selected:
        raise ValueError("missing named Locus cls rows")
    return selected["cls"]


def compare(scalars, kit, helper, height, checkpoint, checkpoint_pin, reference, reference_pin):
    height_word = scalars.word(height, "checkpoint height")
    flags = read_checkpoint(kit["rmp"], checkpoint, checkpoint_pin, height)
    tree = kit["tree"]
    digest, ordered = tree.read_export(reference, reference_pin, height)
    if tree.digest(helper, ordered) != digest:
        raise ValueError("reference tree does not reproduce its stated raw ABCI digest")

    def leaf(raw):
        result = subprocess.run([helper.resolve()], input=raw, check=True, capture_output=True)
        value = result.stdout.decode("ascii").strip()
        if not tree.DIGEST.fullmatch(value):
            raise ValueError("local helper returned an invalid digest")
        return bytes.fromhex(value[2:])

    def children(node, label):
        if type(node) is not tuple:
            raise ValueError(f"expected raw {label} branch")
        return dict(node)

    locus = children(children(ordered, "Exchange").get(0), "Locus")
    context = children(locus.get(0), "Context")
    if context.get(2) != leaf(height_word):
        raise ValueError("reference inner Context height leaf mismatch")
    cls = children(locus.get(1), "Locus cls")
    count_matches = cls.get(1) == leaf(scalars.word(len(flags), "cls row count"))
    if flags:
        branch = children(cls.get(0), "Clearinghouse field streams")
        layout_matches = tuple(branch) == tuple(range(19)) and tuple(cls) == (0, 1)
        flags_match = branch.get(5) == leaf(flags)
    else:
        layout_matches = tuple(cls) == (1,)
        flags_match = 0 not in cls
    return {"height": height, "reference_raw_digest": digest, "named_row_count": len(flags),
            "ordered_count_matches": count_matches, "field_stream_layout_matches": layout_matches,
            "perform_auto_deleveraging_stream_matches": flags_match}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("helpers", type=Path)
    parser.add_argument("hash_driver", type=Path)
    parser.add_argument("height", type=int)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("checkpoint_sha256")
    parser.add_argument("reference", type=Path)
    parser.add_argument("reference_sha256")
    args = parser.parse_args()
    try:
        scalars = load_scalars(args.helpers)
        result = compare(scalars, scalars.load_helpers(args.helpers), args.hash_driver, args.height,
                         args.checkpoint, args.checkpoint_sha256, args.reference, args.reference_sha256)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(2, f"{error}\n")
    print(json.dumps(result, sort_keys=True))
    return int(not all(result[key] for key in ("ordered_count_matches", "field_stream_layout_matches",
                                               "perform_auto_deleveraging_stream_matches")))


if __name__ == "__main__":
    raise SystemExit(main())
