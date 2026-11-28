"""Stage a named node #115 checkpoint cadence into a pinned decoded fixture."""

import argparse
from hashlib import sha256
from pathlib import Path
import struct
import sys

import msgpack

DECODED_SIZE = 0x27A8
DEFAULT_CADENCE = 1000


class CheckpointStream:
    def __init__(self, source):
        self.source = source
        self.digest = sha256()
        self.bytes_read = 0

    def read(self, size):
        data = self.source.read(size)
        self.digest.update(data)
        self.bytes_read += len(data)
        return data


def selected(unpacker, readers):
    fields = {}
    for _ in range(unpacker.read_map_header()):
        name = unpacker.unpack()
        if type(name) is not str:
            raise ValueError("expected named checkpoint fields")
        if name not in readers:
            unpacker.skip()
        elif name in fields:
            raise ValueError(f"duplicate field {name}")
        else:
            fields[name] = readers[name](unpacker)
    return fields


def required(fields, name):
    if name not in fields:
        raise ValueError(f"missing field {name}")
    return fields[name]


def scalar(unpacker):
    return unpacker.unpack()


def context(unpacker):
    return required(selected(unpacker, {"height": scalar}), "height")


def locus(unpacker):
    return required(selected(unpacker, {"ctx": context}), "ctx")


def misc(unpacker):
    return selected(unpacker, {"aci": scalar}).get("aci", 0)


def exchange(unpacker):
    fields = selected(unpacker, {"locus": locus, "msc": misc})
    return required(fields, "locus"), required(fields, "msc")


def read_checkpoint(path, expected_sha256, expected_height):
    with path.open("rb") as source:
        stream = CheckpointStream(source)
        unpacker = msgpack.Unpacker(stream, raw=False)
        try:
            height, raw_cadence = required(selected(unpacker, {"exchange": exchange}), "exchange")
        except msgpack.OutOfData as error:
            raise ValueError("incomplete checkpoint object") from error
        object_end = unpacker.tell()
        while stream.read(65536):
            pass
        if stream.digest.hexdigest() != expected_sha256.lower():
            raise ValueError("checkpoint SHA-256 does not match")
        if object_end != stream.bytes_read:
            raise ValueError("trailing bytes after checkpoint object")
    if type(height) is not int or not 0 <= height < 1 << 64 or height != expected_height:
        raise ValueError("checkpoint height does not match requested u64 height")
    if type(raw_cadence) is not int or not 0 <= raw_cadence < 1 << 64:
        raise ValueError("Exchange.msc.aci must be a u64")
    return raw_cadence or DEFAULT_CADENCE


def stage(image, expected_sha256, height, interval):
    if len(image) != DECODED_SIZE:
        raise ValueError("expected exactly 0x27a8 bytes of decoded state")
    if sha256(image).hexdigest() != expected_sha256.lower():
        raise ValueError("decoded fixture SHA-256 does not match")
    if struct.unpack_from("<Q", image, 0x28)[0] != height:
        raise ValueError("decoded fixture height does not match")
    if type(interval) is not int or not 0 < interval < 1 << 64:
        raise ValueError("resolved cadence must be a positive u64")
    return image[:0x1EA8] + struct.pack("<Q", interval) + image[0x1EB0:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("decoded_state", type=Path)
    parser.add_argument("--checkpoint-sha256", required=True)
    parser.add_argument("--decoded-sha256", required=True)
    parser.add_argument("--height", type=int, required=True)
    arguments = parser.parse_args()
    try:
        interval = read_checkpoint(arguments.checkpoint, arguments.checkpoint_sha256, arguments.height)
        with arguments.decoded_state.open("rb") as source:
            image = source.read(DECODED_SIZE + 1)
        output = stage(image, arguments.decoded_sha256, arguments.height, interval)
    except (ValueError, OSError, TypeError) as error:
        parser.exit(1, f"cannot stage checkpoint cadence: {error}\n")
    sys.stdout.buffer.write(output)


if __name__ == "__main__":
    main()
