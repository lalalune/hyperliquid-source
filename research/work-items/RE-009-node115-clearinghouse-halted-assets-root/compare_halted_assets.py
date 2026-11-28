"""Compare the named complete named Clearinghouse halted-assets subtree with a raw export."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from types import ModuleType

SCALARS = "RE-009-node115-rmp-locus-scalars-root/compare_locus_scalars.py"
SCALARS_SHA = "27fa4574adbbbedd4fda037a1d606f0861f39070abd651d21c2d8de9cbd45940"
FIELD = "halted_assets"


def load_scalars(folder):
    path = folder / SCALARS
    source = path.read_bytes()
    if hashlib.sha256(source).hexdigest() != SCALARS_SHA:
        raise ValueError("Locus scalar helper pin mismatch")
    module = ModuleType("cls_locus_scalars")
    exec(compile(source, str(path), "exec"), module.__dict__)
    return module


def read_checkpoint(rmp, word, file, pin, height):
    import msgpack

    def collection(u):
        counts = bytearray()
        assets = bytearray()
        clearinghouses = u.read_array_header()
        def asset_array(values):
            count = values.read_array_header()
            previous = -1
            for _ in range(count):
                asset = rmp.read_value(values)
                encoded = word(asset, "halted asset ID")
                if asset <= previous:
                    raise ValueError("expected canonical ascending unique halted asset IDs")
                previous = asset
                assets.extend(encoded)
            return count

        for _ in range(clearinghouses):
            count = rmp.require(u, FIELD, asset_array)
            counts.extend(word(count, "halted asset set length"))
        return clearinghouses, counts, assets

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
    count, counts, assets = read_checkpoint(kit["rmp"], scalars.word, checkpoint, checkpoint_pin, height)
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
    count_matches = cls.get(1) == leaf(scalars.word(count, "cls row count"))
    if count:
        rows = children(cls.get(0), "Clearinghouse field streams")
        expected = ((1, leaf(counts)),)
        if assets:
            expected = ((0, leaf(assets)),) + expected
        assets_match = rows.get(9) == expected
    else:
        assets_match = 0 not in cls
    return {"height": height, "reference_raw_digest": digest, "named_row_count": count,
            "ordered_count_matches": count_matches, "ordered_halted_assets_match": assets_match}


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
    return int(not (result["ordered_count_matches"] and result["ordered_halted_assets_match"]))


if __name__ == "__main__":
    raise SystemExit(main())
