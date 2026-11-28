"""Stage the selected local #115 hardfork and freeze fields from a named RMP file."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys

import msgpack

DECODED_SIZE = 0x27A8


class PinnedReader:
    def __init__(self, source):
        self.source = source
        self.digest = sha256()
        self.bytes_read = 0

    def read(self, count):
        data = self.source.read(count)
        self.digest.update(data)
        self.bytes_read += len(data)
        return data


def members(unpacker, readers):
    selected = {}
    for _ in range(unpacker.read_map_header()):
        key = unpacker.unpack()
        if type(key) is not str:
            raise ValueError("expected named checkpoint fields")
        reader = readers.get(key)
        if reader is None:
            unpacker.skip()
        elif key in selected:
            raise ValueError(f"duplicate field {key}")
        else:
            selected[key] = reader(unpacker)
    return selected


def required(data, name):
    if name not in data:
        raise ValueError(f"missing field {name}")
    return data[name]


def read_scalar(unpacker):
    return unpacker.unpack()


def hardfork_map(unpacker):
    fields = members(unpacker, {"version": read_scalar, "round": read_scalar})
    return required(fields, "version"), required(fields, "round")


def context_map(unpacker):
    fields = members(unpacker, {"height": read_scalar, "hardfork": hardfork_map})
    return required(fields, "height"), fields.get("hardfork", (0, 0))


def locus_map(unpacker):
    return required(members(unpacker, {"ctx": context_map}), "ctx")


def exchange_map(unpacker):
    fields = members(unpacker, {"locus": locus_map, "scheduled_freeze_height": read_scalar})
    (height, pair) = required(fields, "locus")
    return height, pair, fields.get("scheduled_freeze_height")


def u64(value, field):
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError(f"{field} must be a u64")
    return value


def read_checkpoint(path, expected_sha256, requested_height):
    with path.open("rb") as source:
        reader = PinnedReader(source)
        unpacker = msgpack.Unpacker(reader, raw=False)
        try:
            height, pair, freeze = required(members(unpacker, {"exchange": exchange_map}), "exchange")
        except msgpack.OutOfData as error:
            raise ValueError("incomplete named checkpoint") from error
        end = unpacker.tell()
        while reader.read(65536):
            pass
        if reader.digest.hexdigest() != expected_sha256.lower():
            raise ValueError("checkpoint SHA-256 does not match")
        if end != reader.bytes_read:
            raise ValueError("trailing bytes after checkpoint")
    if u64(height, "height") != requested_height:
        raise ValueError("checkpoint height does not match")
    return {
        "height": height,
        "hardfork_version": u64(pair[0], "hardfork.version"),
        "hardfork_round": u64(pair[1], "hardfork.round"),
        "scheduled_freeze": None if freeze is None else u64(freeze, "scheduled_freeze_height"),
    }


def stage(image, image_sha256, fields):
    if len(image) != DECODED_SIZE:
        raise ValueError("decoded fixture must contain exactly 0x27a8 bytes")
    if sha256(image).hexdigest() != image_sha256.lower():
        raise ValueError("decoded fixture SHA-256 does not match")
    if struct.unpack_from("<Q", image, 0x28)[0] != fields["height"]:
        raise ValueError("decoded fixture height does not match")
    result = bytearray(image)
    struct.pack_into("<QQ", result, 0x18, fields["hardfork_version"], fields["hardfork_round"])
    target = fields["scheduled_freeze"]
    struct.pack_into("<Q", result, 0x10E8, int(target is not None))
    if target is not None:
        struct.pack_into("<Q", result, 0x10F0, target)
    return bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--height", type=int, required=True)
    parser.add_argument("--decoded-state", type=Path)
    parser.add_argument("--decoded-sha256")
    arguments = parser.parse_args()
    if bool(arguments.decoded_state) != bool(arguments.decoded_sha256):
        parser.error("provide both --decoded-state and --decoded-sha256")
    try:
        fields = read_checkpoint(arguments.checkpoint, arguments.sha256, arguments.height)
        if arguments.decoded_state:
            with arguments.decoded_state.open("rb") as source:
                image = source.read(DECODED_SIZE + 1)
            staged = stage(image, arguments.decoded_sha256, fields)
    except (OSError, ValueError, TypeError) as error:
        parser.exit(1, f"cannot stage local checkpoint fields: {error}\n")
    if arguments.decoded_state:
        sys.stdout.buffer.write(staged)
    else:
        print(json.dumps(fields, sort_keys=True))


if __name__ == "__main__":
    main()
