"""Compare complete #115 Locus uac raw subtree using an independently supplied compact count."""

import argparse
import hashlib
import json
import re
from pathlib import Path
import subprocess
from types import ModuleType

ACTIVITY_FILE = "RE-009-node115-rmp-locus-ctr-ac-root/compare_locus_activity.py"
ACTIVITY_SHA = "2358d653bc582c1633697b4066c94f8b20d3bbe5902e95263968e9edeaa56f1a"
ADDRESS = re.compile(r"0x[0-9a-f]{40}")


def load_helpers(folder):
    path = folder / ACTIVITY_FILE
    source = path.read_bytes()
    if hashlib.sha256(source).hexdigest() != ACTIVITY_SHA:
        raise ValueError("activity projection source pin mismatch")
    activity = ModuleType("node115_uac_activity")
    exec(compile(source, str(path), "exec"), activity.__dict__)
    return activity, activity.load_helpers(folder)


def read_count(tree, path, pin, height, checkpoint_pin, word):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != pin:
        raise ValueError("compact count witness SHA-256 mismatch")
    row = json.loads(data, object_pairs_hook=tree.unique_fields)
    if type(row) is not dict or set(row) != {"height", "checkpoint_sha256", "uac_compact_count"}:
        raise ValueError("expected a compact count witness with height and checkpoint SHA-256")
    if type(row["height"]) is not int or row["height"] != height or row["checkpoint_sha256"] != checkpoint_pin:
        raise ValueError("compact count witness is bound to a different checkpoint")
    return row["uac_compact_count"], word(row["uac_compact_count"], "compact uac count")


def read_checkpoint(activity, kit, path, pin, height):
    import msgpack

    rmp = kit["rmp"]

    names = activity.DIRECT + activity.GROUPS + activity.CLOCKS

    def grouped(u, keys):
        return rmp.select(u, dict.fromkeys(keys, rmp.read_value))

    def row(u):
        def words(v):
            return grouped(v, activity.FIVE_WORDS)

        def timed(v):
            return grouped(v, ("n", "t"))

        return rmp.select(u, {**dict.fromkeys(activity.DIRECT, rmp.read_value),
                              **dict.fromkeys(activity.GROUPS, words),
                              **dict.fromkeys(activity.CLOCKS, timed)})

    def collection(u):
        count = u.read_array_header()
        users = set()
        addresses = bytearray()
        streams = {key: [bytearray() for _ in range(width)] for key, width in zip(names, (1, 1, 1, 1, 5, 5, 5, 2, 2))}
        for index in range(count):
            if u.read_array_header() != 2:
                raise ValueError(f"expected a pair at uac row {index}")
            key = u.unpack()
            if type(key) is str and ADDRESS.fullmatch(key):
                address = bytes.fromhex(key[2:])
            elif type(key) is list and len(key) == 20 and all(type(v) is int and 0 <= v < 256 for v in key):
                address = bytes(key)
            else:
                raise ValueError(f"expected a 20-byte uac Address at row {index}")
            if address in users:
                raise ValueError("duplicate uac Address")
            users.add(address)
            addresses.extend(address)
            fields = row(u)
            for key in activity.DIRECT:
                streams[key][0].extend(activity.word(fields.get(key, 0), key))
            for key in activity.GROUPS:
                group = fields.get(key, {})
                for dst, subkey in zip(streams[key], activity.FIVE_WORDS):
                    dst.extend(activity.word(group.get(subkey, 0), f"{key}.{subkey}"))
            for key in activity.CLOCKS:
                pair = fields.get(key, {})
                streams[key][0].extend(activity.word(pair.get("n", 0), f"{key}.n"))
                clock = kit["normalize"].clock(pair.get("t", activity.EPOCH))
                streams[key][1].extend(kit["clock"].clock(clock))
        return count, addresses, streams

    def locus(u):
        return rmp.select(u, {"uac": collection,
                              "ctx": lambda ctx: rmp.require(ctx, "height", rmp.read_value)})

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
    if "uac" not in fields:
        raise ValueError("checkpoint omits Locus uac")
    return fields["uac"]


def compare(activity, kit, helper, height, checkpoint, checkpoint_pin, reference, reference_pin, count_path, count_pin):
    height_word = activity.word(height, "checkpoint height")
    named_count, addresses, streams = read_checkpoint(activity, kit, checkpoint, checkpoint_pin, height)
    tree = kit["tree"]
    compact_count, raw_count = read_count(tree, count_path, count_pin, height, checkpoint_pin, activity.word)
    digest, ordered = tree.read_export(reference, reference_pin, height)
    if tree.digest(helper, ordered) != digest:
        raise ValueError("reference tree does not reproduce its stated raw ABCI digest")

    def children(node, label):
        if type(node) is not tuple:
            raise ValueError(f"expected a raw {label} branch")
        return dict(node)

    def leaf(raw):
        output = subprocess.run([helper.resolve()], input=raw, check=True, capture_output=True)
        value = output.stdout.decode("ascii").strip()
        if not tree.DIGEST.fullmatch(value):
            raise ValueError("local helper returned an invalid digest")
        return bytes.fromhex(value[2:])

    locus = children(children(ordered, "Exchange").get(0), "Locus")
    context = children(locus.get(0), "Context")
    if context.get(2) != leaf(height_word):
        raise ValueError("reference inner Context height leaf mismatch")
    expected = ((2, leaf(raw_count)),)
    if named_count:
        value_branch = tuple((index, leaf(raw[0]) if len(raw) == 1 else
                              tuple((child, leaf(data)) for child, data in enumerate(raw)))
                             for index, raw in enumerate(streams.values()))
        expected = ((0, leaf(addresses)), (1, value_branch)) + expected
    actual = locus.get(11)
    parts = dict(actual) if type(actual) is tuple else {}
    intended = dict(expected)
    return {"height": height, "reference_raw_digest": digest, "named_row_count": named_count,
            "compact_count": compact_count, "checkpoint_sha256": checkpoint_pin, "count_witness_sha256": count_pin,
            "address_stream_matches": parts.get(0) == intended.get(0),
            "ordered_values_match": parts.get(1) == intended.get(1),
            "compact_count_matches": parts.get(2) == intended[2], "ordered_uac_matches": actual == expected}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("helpers", type=Path)
    parser.add_argument("hash_helper", type=Path)
    parser.add_argument("height", type=int)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("checkpoint_sha256")
    parser.add_argument("reference", type=Path)
    parser.add_argument("reference_sha256")
    parser.add_argument("count_witness", type=Path)
    parser.add_argument("count_witness_sha256")
    args = parser.parse_args()
    try:
        result = compare(*load_helpers(args.helpers), args.hash_helper, args.height, args.checkpoint,
                         args.checkpoint_sha256, args.reference, args.reference_sha256,
                         args.count_witness, args.count_witness_sha256)
    except (ValueError, OSError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ordered_uac_matches"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
