"""Drive paired reconstructed engine root checks from pinned checkpoint fields."""

import hashlib
import json
import re

import msgpack


def controls(path, digest, height, positional):
    fields = positional.project(path, digest, height)

    def named_items(unpacker, readers):
        result = {}
        for _ in range(unpacker.read_map_header()):
            key = unpacker.unpack()
            if type(key) is not str:
                raise ValueError("expected named checkpoint field")
            if key not in readers:
                unpacker.skip()
                continue
            if key in result:
                raise ValueError(f"duplicate selected field {key}")
            result[key] = readers[key](unpacker)
        return result

    def hardfork(unpacker):
        length = unpacker.read_array_header()
        if length < 2:
            raise ValueError("missing positional hardfork field")
        unpacker.skip()
        child = named_items(unpacker, {word: msgpack.Unpacker.unpack for word in ("version", "round")})
        if set(child) != {"version", "round"}:
            raise ValueError("missing hardfork version or round")
        for _ in range(length - 2):
            unpacker.skip()
        return [positional.unsigned_word(child[word], f"hardfork {word}") for word in ("version", "round")]

    with path.open("rb") as source:
        stream = positional.DigestStream(source)
        unpacker = msgpack.Unpacker(stream, raw=False)
        result = positional.map_field(unpacker, "exchange", lambda value: named_items(value, {
            "locus": lambda locus: positional.map_field(locus, "ctx", hardfork),
            "msc": lambda msc: named_items(msc, {"aci": msgpack.Unpacker.unpack}),
        }))
        parsed = unpacker.tell()
        while stream.read(65536):
            pass
        if stream.digest.hexdigest() != digest or parsed != stream.size:
            raise ValueError("wrong original checkpoint bytes")
    if set(result) != {"locus", "msc"}:
        raise ValueError("checkpoint is missing locus or msc")
    cadence = positional.unsigned_word(result["msc"].get("aci", 0), "aci")
    return {**fields, "hardfork_words": result["locus"], "cadence": cadence or 1000}


def run(manifest, digest, scratch, positional, paired, probe, encode_tree):
    def require(condition, message):
        if not condition:
            raise ValueError(message)

    data = manifest.read_bytes()
    require(hashlib.sha256(data).hexdigest() == digest, "wrong case SHA-256")
    spec = json.loads(data, object_pairs_hook=paired.unique)
    require(set(spec) == {"height", "checkpoint_rmp", "wire", "reference_h", "reference_h_plus_one",
                          "fixture_inputs"}, "wrong fixture manifest")
    checkpoint = spec["checkpoint_rmp"]
    require(type(checkpoint) is dict and set(checkpoint) == {"path", "sha256"}, "wrong checkpoint artifact")
    height = positional.unsigned_word(spec["height"], "source height")
    observed = controls((manifest.parent / checkpoint["path"]).resolve(), checkpoint["sha256"], height, positional)

    hints = spec["fixture_inputs"]
    require(type(hints) is dict and set(hints) == {"persisted_loader_count", "auxiliary_digest"},
            "wrong extra fixture inputs")
    loader = positional.unsigned_word(hints["persisted_loader_count"], "fixture loader count")
    auxiliary = hints["auxiliary_digest"]
    require(type(auxiliary) is str and re.fullmatch(r"[0-9a-f]{64}", auxiliary), "wrong auxiliary digest")
    fixture_path = scratch / "derived-fixture-state.txt"
    fixture = f"{height} {observed['round']} {loader} {observed['cadence']} "
    fixture += f"{observed['hardfork_words'][0]} {observed['hardfork_words'][1]} {auxiliary}"
    fixture_path.write_text(fixture, encoding="ascii")
    scoped = {"height": height, "checkpoint": {"path": str(fixture_path), "sha256": paired.sha(fixture.encode())}}
    for role in ("wire", "reference_h", "reference_h_plus_one"):
        entry = spec[role]
        require(type(entry) is dict and set(entry) == {"path", "sha256"}, f"wrong {role} artifact")
        scoped[role] = {**entry, "path": str((manifest.parent / entry["path"]).resolve())}
    packed = json.dumps(scoped).encode()
    path = scratch / "derived-paired-root-case.json"
    path.write_bytes(packed)
    result = paired.check(path, paired.sha(packed), scratch, probe, encode_tree)
    return {"checkpoint_sha256": checkpoint["sha256"], "restored_checkpoint": observed, **result}
