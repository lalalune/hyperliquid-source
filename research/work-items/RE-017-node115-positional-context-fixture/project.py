"""Read selected node #115 positional Context fields in an offline checkpoint."""

import argparse
from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path
import re
import struct
import sys

import msgpack

DECODED_SIZE = 0x27A8
U64_MAX = (1 << 64) - 1
CLOCK = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.[0-9]{1,9})?")


class DigestStream:
    def __init__(self, stream):
        self.stream = stream
        self.digest = sha256()
        self.size = 0

    def read(self, size):
        data = self.stream.read(size)
        self.digest.update(data)
        self.size += len(data)
        return data


def map_field(unpacker, name, reader):
    result = None
    found = False
    for _ in range(unpacker.read_map_header()):
        key = unpacker.unpack()
        if type(key) is not str:
            raise ValueError(f"expected a named map at the {name} boundary")
        if key != name:
            unpacker.skip()
            continue
        if found:
            raise ValueError(f"duplicate checkpoint field {name}")
        result = reader(unpacker)
        found = True
    if not found:
        raise ValueError(f"missing checkpoint field {name}")
    return result


def unsigned_word(value, name):
    if type(value) is not int or not 0 <= value <= U64_MAX:
        raise ValueError(f"{name} must be an unsigned 64-bit value")
    return value


def clock_text(value, name):
    matched = CLOCK.fullmatch(value) if type(value) is str else None
    if matched is None:
        raise ValueError(f"{name} is outside the supported clock text shape")
    try:
        datetime.fromisoformat(matched.group(1))
    except ValueError as error:
        raise ValueError(f"{name} is outside the supported calendar range") from error
    return value


def read_positions(unpacker):
    count = unpacker.read_array_header()
    if count < 9:
        raise ValueError("positional Context has fewer than nine slots")
    selected = {2: "height", 4: "round", 5: "time", 6: "prev_time"}
    fields = {}
    for index in range(count):
        if index in selected:
            fields[selected[index]] = unpacker.unpack()
        else:
            unpacker.skip()
    return {
        "height": unsigned_word(fields["height"], "height"),
        "round": unsigned_word(fields["round"], "round"),
        "time": clock_text(fields["time"], "time"),
        "prev_time": clock_text(fields["prev_time"], "prev_time"),
    }


def project(path, expected_sha256, height):
    with path.open("rb") as source:
        stream = DigestStream(source)
        unpacker = msgpack.Unpacker(stream, raw=False)
        try:
            projected = map_field(unpacker, "exchange", lambda exchange: map_field(
                exchange, "locus", lambda locus: map_field(locus, "ctx", read_positions),
            ))
        except msgpack.OutOfData as error:
            raise ValueError("incomplete checkpoint object") from error
        parsed_bytes = unpacker.tell()
        while stream.read(65536):
            pass
        if stream.digest.hexdigest() != expected_sha256.lower():
            raise ValueError("checkpoint SHA-256 does not match")
        if parsed_bytes != stream.size:
            raise ValueError("trailing bytes after checkpoint")
    if projected["height"] != height:
        raise ValueError("projected checkpoint height does not match")
    return projected


def stage_round(image, expected_sha256, projection):
    if len(image) != DECODED_SIZE:
        raise ValueError("decoded fixture must contain exactly 0x27a8 bytes")
    if sha256(image).hexdigest() != expected_sha256.lower():
        raise ValueError("decoded fixture SHA-256 does not match")
    if struct.unpack_from("<Q", image, 0x28)[0] != projection["height"]:
        raise ValueError("decoded fixture height does not match checkpoint")
    return image[:0x30] + struct.pack("<Q", projection["round"]) + image[0x38:]


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
        result = project(arguments.checkpoint, arguments.sha256, arguments.height)
        if arguments.decoded_state:
            with arguments.decoded_state.open("rb") as source:
                image = source.read(DECODED_SIZE + 1)
            staged = stage_round(image, arguments.decoded_sha256, result)
    except (OSError, ValueError, TypeError) as error:
        parser.exit(1, f"cannot project positional checkpoint Context: {error}\n")
    if arguments.decoded_state:
        sys.stdout.buffer.write(staged)
    else:
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
