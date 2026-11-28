"""Compare a pinned native archive H+1 header with decoded replay observations."""

from argparse import ArgumentParser
import hashlib
import json
from pathlib import Path
import re

MAX_U64 = (1 << 64) - 1


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError(f"invalid JSON constant {value}")


def load(raw):
    return json.loads(raw, object_pairs_hook=object_pairs, parse_constant=reject_constant)


def u64(value, label):
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise ValueError(f"{label}: expected an unsigned 64-bit integer")
    return value


def artifact(root, entry):
    if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
        raise ValueError("artifact requires path and SHA-256")
    if not isinstance(entry["path"], str) or not entry["path"]:
        raise ValueError("missing artifact path")
    raw = (root / entry["path"]).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != entry["sha256"]:
        raise ValueError(f"{entry['path']}: wrong artifact SHA-256")
    return raw, digest


def fields(block):
    if not isinstance(block, dict):
        raise ValueError("expected Block header")
    hardfork = block.get("hardfork")
    if not isinstance(hardfork, dict):
        raise ValueError("expected hardfork object")
    proposer = block.get("proposer")
    if not isinstance(proposer, str) or re.fullmatch(r"0x[0-9a-f]{40}", proposer) is None:
        raise ValueError("expected fixed 20-byte lowercase proposer")
    time = block.get("time")
    if not isinstance(time, str) or not time:
        raise ValueError("expected archive clock text")
    return {
        "time": time,
        "proposer": proposer,
        "round": u64(block.get("round"), "round"),
        "parent_round": u64(block.get("parent_round"), "parent_round"),
        "hardfork.version": u64(hardfork.get("version"), "hardfork.version"),
        "hardfork.round": u64(hardfork.get("round"), "hardfork.round"),
    }


def audit(manifest_path, observed):
    manifest = load(manifest_path.read_bytes())
    if not isinstance(manifest, dict) or not isinstance(observed, dict):
        raise ValueError("expected manifest and observation objects")
    height = u64(manifest["checkpoint_height"], "checkpoint height")
    if height == MAX_U64:
        raise ValueError("missing representable height H+1")
    _, wire_digest = artifact(manifest_path.parent, manifest["wire"])
    raw, archive_digest = artifact(manifest_path.parent, manifest["archive"])
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise ValueError("expected one complete native archive line")
    archived = load(raw)
    if not isinstance(archived, dict):
        raise ValueError("expected native archive row object")
    declared = u64(archived.get("height"), "archive height")
    if declared != height + 1:
        raise ValueError(f"archive height {declared} differs from H+1 ({height + 1})")
    if observed.get("wire_sha256") != wire_digest:
        raise ValueError("observations name a different wire input")
    expected = fields(archived.get("abci_block"))
    actual = fields(observed.get("abci_block"))
    differences = {
        name: {"archive": expected[name], "decoded": actual[name]}
        for name in expected
        if expected[name] != actual[name]
    }
    return {
        "height": declared,
        "wire_sha256": wire_digest,
        "archive_sha256": archive_digest,
        "compared": list(expected),
        "differences": differences,
    }


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("observations", type=Path)
    opts = parser.parse_args()
    try:
        result = audit(opts.manifest, load(opts.observations.read_bytes()))
    except (KeyError, OSError, TypeError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result))
    return int(bool(result["differences"]))


if __name__ == "__main__":
    raise SystemExit(main())
