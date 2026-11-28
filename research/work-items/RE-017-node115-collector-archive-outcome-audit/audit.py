"""Align a retained Full result prefix against an independent native archive."""

from argparse import ArgumentParser
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
import sys
from types import ModuleType

MAX_U64 = (1 << 64) - 1
COMPARATOR_SHA256 = "67133b189a51608c12b560977f2e43f97896db241879f2a011d4352172fc9b61"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError(f"invalid JSON constant {value}")


def load(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                      parse_float=Decimal, parse_constant=reject_constant)


def dump(value):
    """Encode an excerpt without rounding the row's numeric outcomes."""
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(key) + ":" + dump(item) for key, item in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ",".join(dump(item) for item in value) + "]"
    return json.dumps(value)


def indexed(rows, label):
    require(isinstance(rows, list), f"{label} requires rows")
    result = {}
    for row in rows:
        require(isinstance(row, list) and len(row) == 2, f"{label} requires key/value rows")
        key, payload = row
        require(isinstance(key, str) and re.fullmatch(r"0x[0-9a-f]{64}", key), "invalid bundle key")
        require(key not in result, f"ambiguous key in {label}: {key}")
        result[key] = payload
    return result


def u64(value, label):
    require(type(value) is int and 0 <= value <= MAX_U64, f"invalid {label}")
    return value


def artifact(base, item):
    raw = (base / item["path"]).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    require(digest == item["sha256"], f"wrong artifact SHA-256 for {item['path']}")
    return raw


def compare_prefix(manifest_path, compare):
    manifest = load(manifest_path.read_bytes())
    archive_raw = artifact(manifest_path.parent, manifest["archive"])
    observation = load(artifact(manifest_path.parent, manifest["observation"]))
    require(archive_raw.endswith(b"\n") and archive_raw.count(b"\n") == 1, "expected one archive line")
    archived = load(archive_raw)
    height = u64(manifest["checkpoint_height"], "checkpoint height")
    require(height < MAX_U64 and u64(archived["height"], "archive height") == height + 1,
            "expected explicit archive height H+1")
    require(u64(observation["height"], "observation height") == height + 1,
            "expected explicit observation height H+1")
    ordinals, stop = observation["ordinals"], observation["stop_position"]
    require(isinstance(ordinals, list), "expected ordered collector metadata")
    require(stop is None or u64(stop, "stop position") == len(ordinals), "wrong explicit stop position")
    require(isinstance(observation["resps"], dict) and set(observation["resps"]) == {"Full"},
            "expected observed Full result")
    observed = indexed(observation["resps"]["Full"], "observed Full")
    require(len(ordinals) == len(observed), "collector metadata count differs from Full rows")
    sources = {key: u64(ordinal, "source ordinal") for key, ordinal in zip(observed, ordinals)}
    require(len(set(sources.values())) == len(sources), "ambiguous source ordinal")

    native = archived["resps"]
    require(isinstance(native, dict) and set(native) == {"Full"}, "expected archived Full result")
    require(compare(archive_raw, dump(native).encode()) == (), "archive Full is internally inconsistent")
    expected = indexed(native["Full"], "archived Full")
    require(observed.keys() <= expected.keys(), "observed bundle key is absent from archive")
    block = archived["abci_block"]
    observed_geometry = [row for row in block["signed_action_bundles"] if row[0] in observed]
    excerpt = {"abci_block": {**block, "signed_action_bundles": observed_geometry},
               "resps": {"Full": [[key, expected[key]] for key, _ in observed_geometry]}}
    differences = compare(dump(excerpt).encode(), dump(observation["resps"]).encode())
    missing = [row[0] for row in block["signed_action_bundles"] if row[0] not in observed]
    return {
        "height": height + 1,
        "archive_sha256": manifest["archive"]["sha256"],
        "observation_sha256": manifest["observation"]["sha256"],
        "coverage": ("partial" if observed else "none") if missing else "complete",
        "observed": [{"bundle": key, "source_ordinal": ordinal} for key, ordinal in sources.items()],
        "missing": missing,
        "stop_position": stop,
        "differences": [
            {"bundle": f"0x{item.bundle.hex()}", "source_ordinal": sources[f"0x{item.bundle.hex()}"],
             "action_index": item.action_index, "fields": list(item.fields)}
            for item in differences
        ],
    }


def existing_comparator(path):
    source = path.read_bytes()
    require(hashlib.sha256(source).hexdigest() == COMPARATOR_SHA256, "wrong comparator source")
    module = ModuleType("existing_replica_compare")
    sys.modules[module.__name__] = module
    exec(compile(source, str(path), "exec"), module.__dict__)
    return module.compare


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("comparison_source", type=Path)
    opts = parser.parse_args()
    try:
        report = compare_prefix(opts.manifest, existing_comparator(opts.comparison_source))
    except (KeyError, OSError, TypeError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(report))
    return int(bool(report["differences"]))


if __name__ == "__main__":
    raise SystemExit(main())
