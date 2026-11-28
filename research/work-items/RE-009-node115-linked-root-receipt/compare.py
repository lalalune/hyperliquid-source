"""Link pinned node #115 checkpoint serializer bytes to two distinct digest records."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

U64_MAX = (1 << 64) - 1
DIGEST = re.compile(r"0x[0-9a-f]{64}")
SHA256 = re.compile(r"[0-9a-f]{64}")


def pinned(path, sha):
    data = path.read_bytes()
    if not SHA256.fullmatch(sha) or hashlib.sha256(data).hexdigest() != sha:
        raise ValueError(f"SHA-256 mismatch for {path}")
    return data


def unique_fields(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate export key")
    return result


def raw_digest(data, height):
    row = json.loads(data, object_pairs_hook=unique_fields)
    if type(row) is not dict or set(row) != {"height", "abci_digest", "exchange_abci_hash"}:
        raise ValueError("expected a native three-field abci_hashes record")
    if type(row["height"]) is not int or row["height"] != height:
        raise ValueError("raw ABCI record height differs from the requested height")
    value = row["abci_digest"]
    if type(value) is not str or not DIGEST.fullmatch(value):
        raise ValueError("expected a canonical raw 32-byte ABCI digest")
    return value


def reference_linked(data, height):
    if len(data) != 40:
        raise ValueError("expected one 40-byte native hardfork_hashes message")
    if int.from_bytes(data[:8], "little") != height:
        raise ValueError("hardfork_hashes message height differs from the requested height")
    return "0x" + data[8:].hex()


def compute(helper, state, state_sha, raw):
    if not SHA256.fullmatch(state_sha):
        raise ValueError("invalid serializer SHA-256")
    measured = hashlib.sha256()
    size = 0
    with state.open("rb") as source, subprocess.Popen(
        [helper.resolve(), raw[2:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    ) as child:
        for part in iter(lambda: source.read(65536), b""):
            measured.update(part)
            size += len(part)
            child.stdin.write(part)
        child.stdin.close()
        values = child.stdout.read().decode("ascii").splitlines()
        if child.wait() != 0:
            raise ValueError("local linked digest helper failed")
    if measured.hexdigest() != state_sha:
        raise ValueError("serialized state SHA-256 mismatch")
    if len(values) != 2 or not all(DIGEST.fullmatch(value) for value in values):
        raise ValueError("local linked digest helper returned an invalid result")
    return size, *values


def compare(helper, height, state, state_sha, raw_export, raw_sha, linked_message, linked_sha):
    if type(height) is not int or not 0 <= height <= U64_MAX:
        raise ValueError("height must be an unsigned 64-bit integer")
    raw = raw_digest(pinned(raw_export, raw_sha), height)
    expected = reference_linked(pinned(linked_message, linked_sha), height)
    state_size, inner, linked = compute(helper, state, state_sha, raw)
    return {
        "height": height,
        "serialized_state_bytes": state_size,
        "serialized_state_blake3": inner,
        "raw_abci_digest": raw,
        "computed_linked_l1_digest": linked,
        "reference_linked_l1_digest": expected,
        "linked_match": linked == expected,
    }


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("helper", type=Path)
    cli.add_argument("height", type=int)
    cli.add_argument("state", type=Path)
    cli.add_argument("state_sha256")
    cli.add_argument("raw_export", type=Path)
    cli.add_argument("raw_export_sha256")
    cli.add_argument("linked_message", type=Path)
    cli.add_argument("linked_message_sha256")
    args = cli.parse_args()
    try:
        result = compare(args.helper, args.height, args.state, args.state_sha256,
                         args.raw_export, args.raw_export_sha256,
                         args.linked_message, args.linked_message_sha256)
    except (OSError, ValueError, RecursionError, subprocess.SubprocessError) as error:
        cli.error(str(error))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["linked_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
