"""Check begin-derived Context leaves at a checkpoint and its first replay height."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
from types import ModuleType

MAX_HEIGHT = 2**64 - 1
TREE_CODEC_SHA = "acb3c71a3c56b42d9614aeb78225cfc90f364e8468db144c0f55e22a175fc3ec"
SLOTS = {"height": 2, "round": 4, "time": 5, "prev_time": 6}
ROLES = ("restored_context", "successor_header", "reference_h", "reference_h_plus_one")


def u64(value, label):
    if type(value) is not int or not 0 <= value <= MAX_HEIGHT:
        raise ValueError(f"{label} must be a u64")
    return value


def clock_tuple(value):
    if type(value) is not dict or set(value) != {"unix_seconds", "subsec_nanos"}:
        raise ValueError("expected normalized ordinary clock")
    seconds, nanos = value["unix_seconds"], value["subsec_nanos"]
    if (type(seconds) is not int or not -62135596800 <= seconds <= 253402300799
            or type(nanos) is not int or not 0 <= nanos < 10**9):
        raise ValueError("clock seconds or nanos outside supported range")
    return seconds, nanos


def transition(restored, successor):
    height = u64(restored["height"], "checkpoint height")
    if height == MAX_HEIGHT or u64(successor["height"], "successor height") != height + 1:
        raise ValueError("expected successor at the immediate H+1 archive coordinate")
    current, previous = clock_tuple(restored["time"]), clock_tuple(restored["prev_time"])
    incoming = clock_tuple(successor["time"])
    rotated = incoming > current
    return (
        (height, u64(restored["round"], "restored round"), current, previous),
        (height + 1, u64(successor["round"], "incoming round"),
         incoming if rotated else current, current if rotated else previous),
        rotated,
    )


def encoded(values):
    return {
        "height": values[0].to_bytes(8, "little"),
        "round": values[1].to_bytes(8, "little"),
        "time": struct.pack("<qI", *values[2]),
        "prev_time": struct.pack("<qI", *values[3]),
    }


def read_unique(pairs):
    result = dict(pairs)
    if len(pairs) != len(result):
        raise ValueError("duplicate JSON field")
    return result


def pinned_json(path, expected):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f"SHA-256 mismatch for {path}")
    value = json.loads(data, object_pairs_hook=read_unique)
    if type(value) is not dict:
        raise ValueError(f"expected JSON object in {path}")
    return value


def load_tree_codec(path):
    source = path.read_bytes()
    if hashlib.sha256(source).hexdigest() != TREE_CODEC_SHA:
        raise ValueError("expected the pinned #7404 tree codec")
    module = ModuleType("node115_root_codec")
    module.__file__ = str(path)
    exec(compile(source, str(path), "exec"), module.__dict__)
    return module


def compare_export(tree_codec, helper, record, values):
    stated, tree = tree_codec.read_export(*record, values[0])
    if tree_codec.digest(helper, tree) != stated:
        raise ValueError(f"height {values[0]} reference tree disagrees with its recorded raw digest")
    subtree = dict(tree_codec.at_path(tree, (0, 0)))
    matched = {}
    for name, preimage in encoded(values).items():
        result = subprocess.run([helper.resolve()], input=preimage, check=True, capture_output=True)
        text = result.stdout.decode("ascii").strip()
        if not tree_codec.DIGEST.fullmatch(text):
            raise ValueError("BLAKE3 helper returned an invalid slot digest")
        expected = bytes.fromhex(text[2:])
        matched[name] = subtree.get(SLOTS[name]) == expected
    return {"height": values[0], "reference_raw_digest": stated, "matched": matched}


def compare_manifest(manifest, sha, tree_codec, helper):
    items = pinned_json(manifest, sha)
    if set(items) != set(ROLES):
        raise ValueError(f"expected exactly the artifact roles {', '.join(ROLES)}")
    refs = {}
    for role, value in items.items():
        if type(value) is not dict or set(value) != {"path", "sha256"}:
            raise ValueError(f"expected path and SHA-256 for {role}")
        refs[role] = manifest.parent / value["path"], value["sha256"]
    before, after, rotated = transition(
        pinned_json(*refs["restored_context"]), pinned_json(*refs["successor_header"]),
    )
    return {
        "clock_rotated": rotated,
        "h_context": compare_export(tree_codec, helper, refs["reference_h"], before),
        "h_plus_one_begin_projection": compare_export(tree_codec, helper, refs["reference_h_plus_one"], after),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tree_codec", type=Path)
    parser.add_argument("helper", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("manifest_sha256")
    args = parser.parse_args()
    try:
        codec = load_tree_codec(args.tree_codec)
        result = compare_manifest(args.manifest, args.manifest_sha256, codec, args.helper)
    except (KeyError, TypeError, ValueError, OSError, RecursionError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))
    return 0 if all(
        all(result[key]["matched"].values()) for key in ("h_context", "h_plus_one_begin_projection")
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
