"""Stream a named node #115 MessagePack checkpoint into Context root inputs."""

import argparse
import hashlib
import json
from pathlib import Path
from types import ModuleType

PROJECTOR_SHA = "5b8f909500007bc23aa6ce46d0d9abf79fab081e6a35a68587d07edec95bbebd"
FIELDS = {
    "initial_height", "hardfork_height", "hardfork", "height", "tx_index", "round",
    "consensus_round", "time", "prev_time", "next_oid", "next_lid", "next_twap_id",
    "system_nonce", "use_system_nonce", "mac",
}


class HashingReader:
    """Feed the decoder and the pin check from the same byte stream."""

    def __init__(self, stream):
        self.stream = stream
        self.digest = hashlib.sha256()
        self.count = 0

    def read(self, size):
        data = self.stream.read(size)
        self.digest.update(data)
        self.count += len(data)
        return data


def select(unpacker, readers):
    fields = {}
    for _ in range(unpacker.read_map_header()):
        key = unpacker.unpack()
        if type(key) is not str:
            raise ValueError("expected a named checkpoint map")
        reader = readers.get(key)
        if reader is None:
            unpacker.skip()
            continue
        if key in fields:
            raise ValueError(f"duplicate checkpoint field {key}")
        fields[key] = reader(unpacker)
    return fields


def require(unpacker, key, reader):
    value = select(unpacker, {key: reader})
    if key not in value:
        raise ValueError(f"missing checkpoint field {key}")
    return value[key]


def read_value(unpacker):
    return unpacker.unpack()


def hardfork(unpacker):
    return select(unpacker, {"version": read_value, "round": read_value})


def context(unpacker):
    fields = select(unpacker, {**dict.fromkeys(FIELDS, read_value), "hardfork": hardfork})
    if "initial_height" in fields:
        if "hardfork_height" in fields:
            raise ValueError("initial_height and hardfork_height denote the same field")
        fields["hardfork_height"] = fields.pop("initial_height")
    return fields


def read_context(path, expected_sha):
    import msgpack

    with path.open("rb") as stream:
        reader = HashingReader(stream)
        unpacker = msgpack.Unpacker(reader, raw=False)
        try:
            state = require(unpacker, "exchange", lambda u: require(
                u, "locus", lambda locus: require(locus, "ctx", context)
            ))
        except msgpack.OutOfData as error:
            raise ValueError("incomplete named checkpoint object") from error
        position = unpacker.tell()
        while reader.read(65536):
            pass
        if reader.digest.hexdigest() != expected_sha:
            raise ValueError("checkpoint file SHA-256 mismatch")
        if position != reader.count:
            raise ValueError("trailing bytes after checkpoint object")
    return state


def load_projector(path):
    source = path.read_bytes()
    if hashlib.sha256(source).hexdigest() != PROJECTOR_SHA:
        raise ValueError("expected the pinned #7368 normalization helper")
    module = ModuleType("node115_context_normalizer")
    module.__file__ = str(path)
    exec(compile(source, str(path), "exec"), module.__dict__)
    return module


def project_rmp(path, sha, requested_height, normalizer):
    state = read_context(path, sha)
    # Preserve the established root input domain and defaults across encodings.
    named_json = json.dumps({"exchange": {"locus": {"ctx": state}}})
    return normalizer.project(named_json, requested_height)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("normalizer", type=Path)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--height", required=True, type=int)
    args = parser.parse_args()
    try:
        output = project_rmp(args.checkpoint, args.sha256, args.height, load_projector(args.normalizer))
    except (ValueError, OSError, TypeError, RecursionError) as error:
        parser.error(str(error))
    print(json.dumps(output, sort_keys=True))


if __name__ == "__main__":
    main()
