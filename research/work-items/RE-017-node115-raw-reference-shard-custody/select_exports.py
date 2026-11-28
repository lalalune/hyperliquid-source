"""Select exact H and H+1 abci_hashes rows from pinned raw export streams."""

from argparse import ArgumentParser
import hashlib
import json
from pathlib import Path
import re

SHA = re.compile(r"[0-9a-f]{64}")
MAX_U64 = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique(fields):
    result = dict(fields)
    require(len(result) == len(fields), "duplicate JSON field")
    return result


def invalid(value):
    raise ValueError(f"invalid JSON constant {value}")


def parse(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=invalid)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def u64(value):
    return type(value) is int and 0 <= value <= MAX_U64


def pin(value):
    return isinstance(value, str) and SHA.fullmatch(value) is not None


def select(manifest, expected):
    raw_manifest = manifest.read_bytes()
    require(digest(raw_manifest) == expected, "wrong manifest SHA-256")
    spec = parse(raw_manifest)
    require(isinstance(spec, dict) and set(spec) == {"height", "shards"}, "bad reference manifest")
    height, shards = spec["height"], spec["shards"]
    require(u64(height) and height < MAX_U64, "invalid checkpoint height")
    require(isinstance(shards, list) and shards, "expected reference shards")
    targets = {height, height + 1}
    selected = {}
    for shard_number, shard in enumerate(shards):
        require(isinstance(shard, dict) and set(shard) == {"path", "sha256"}
                and pin(shard["sha256"]), "wrong shard declaration")
        path = manifest.parent / shard["path"]
        cumulative = hashlib.sha256()
        offset = 0
        with path.open("rb") as stream:
            for number, line in enumerate(stream, 1):
                cumulative.update(line)
                row = parse(line)
                require(line.endswith(b"\n") and isinstance(row, dict) and
                        set(row) == {"height", "exchange_abci_hash", "abci_digest"},
                        f"{shard_number}:{number}: expected one complete abci_hashes row")
                observed, raw_root = row["height"], row["abci_digest"]
                require(u64(observed) and isinstance(raw_root, str) and raw_root.startswith("0x")
                        and pin(raw_root[2:]) and isinstance(row["exchange_abci_hash"], (list, str)),
                        f"{shard_number}:{number}: bad ABCI height, digest or tree")
                if observed in targets:
                    require(observed not in selected, f"ambiguous raw reference height {observed}")
                    selected[observed] = (line, {
                        "source_shard": shard_number,
                        "source_path": shard["path"],
                        "source_sha256": shard["sha256"],
                        "line_number": number,
                        "byte_offset": offset,
                        "byte_length": len(line),
                        "row_sha256": digest(line),
                        "declared_abci_digest": raw_root,
                    })
                offset += len(line)
        require(cumulative.hexdigest() == shard["sha256"], f"wrong complete shard SHA-256 at index {shard_number}")

    require(set(selected) == targets, f"raw reference heights absent: {sorted(targets - selected.keys())}")
    return height, selected


def write_bundle(output, height, selected):
    output.mkdir()
    bindings = {}
    coordinates = {}
    for role, value in (("reference_h", height), ("reference_h_plus_one", height + 1)):
        line, receipt = selected[value]
        name = f"raw-height-{value}.jsonl"
        (output / name).write_bytes(line)
        bindings[role] = {"path": name, "sha256": receipt["row_sha256"]}
        coordinates[role] = receipt
    return {"height": height, "reference_files": bindings, "source_coordinates": coordinates}


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("manifest_sha256")
    parser.add_argument("output", type=Path)
    options = parser.parse_args()
    try:
        height, selected = select(options.manifest, options.manifest_sha256)
        report = write_bundle(options.output, height, selected)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.error(str(error))
    print(json.dumps(report))


if __name__ == "__main__":
    main()
