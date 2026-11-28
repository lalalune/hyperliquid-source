"""Compare two #115 raw ABCI reference heights against offline observations."""

from argparse import ArgumentParser
import hashlib
import json
from pathlib import Path
import re

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
RAW_KIND = "abci_raw"
DIGEST = re.compile(r"0x[0-9a-f]{64}")
MAX_HEIGHT = (1 << 64) - 1


def distinct_pairs(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError(f"duplicate field: {name}")
        result[name] = value
    return result


def object_row(data):
    row = json.loads(data, object_pairs_hook=distinct_pairs)
    if not isinstance(row, dict):
        raise ValueError("expected a JSON object")
    return row


def height(value):
    if type(value) is not int or not 0 <= value <= MAX_HEIGHT:
        raise ValueError("height must be an unsigned 64-bit integer")
    return value


def digest(value):
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise ValueError("expected a raw 32-byte digest encoded as lowercase 0x hex")
    return value


def read_capture(path, anchor, network, observed):
    manifest = object_row(path.read_bytes())
    if manifest.get("network") != network:
        raise ValueError("capture network differs from requested network")
    if manifest.get("target_sha256") != TARGET or manifest.get("digest_kind") != RAW_KIND:
        raise ValueError("capture target or digest kind differs from node #115 raw ABCI")
    origin = manifest.get("origin")
    if not isinstance(origin, str) or not origin.strip():
        raise ValueError("capture origin is required")
    name = manifest.get("data")
    if not isinstance(name, str) or not name or Path(name).name != name:
        raise ValueError("capture data must identify a basename beside its manifest")

    data = path.with_name(name).read_bytes()
    fingerprint = hashlib.sha256(data).hexdigest()
    if fingerprint != manifest.get("data_sha256"):
        raise ValueError("capture data SHA-256 differs from its manifest")

    selected = {}
    stages = {anchor: "restored", anchor + 1: "replayed"}
    for line in data.splitlines():
        row = object_row(line)
        at = height(row.get("height"))
        if at not in stages:
            continue
        if at in selected:
            raise ValueError(f"duplicate capture row at height {at}")
        if observed:
            if row.get("stage") != stages[at]:
                raise ValueError(f"unexpected offline stage at height {at}")
            selected[at] = digest(row.get("abci_digest"))
        else:
            if not isinstance(row.get("exchange_abci_hash"), (str, list)):
                raise ValueError("reference row is missing its exported ABCI tree")
            selected[at] = digest(row.get("abci_digest"))
    return origin, fingerprint, selected


def reconcile(anchor, network, reference, observation):
    anchor = height(anchor)
    if anchor == MAX_HEIGHT:
        raise ValueError("H+1 is outside the height domain")
    if not network.strip():
        raise ValueError("network is required")
    reference_origin, reference_sha, expected = read_capture(reference, anchor, network, False)
    observed_origin, observed_sha, actual = read_capture(observation, anchor, network, True)
    if reference_origin == observed_origin or reference_sha == observed_sha:
        raise ValueError("reference and observation must identify distinct captures")

    results = []
    for at in (anchor, anchor + 1):
        expected_root = expected.get(at)
        actual_root = actual.get(at)
        if expected_root is None:
            status = "missing_reference"
        elif actual_root is None:
            status = "missing_observation"
        elif expected_root == actual_root:
            status = "match"
        else:
            status = "mismatch"
        results.append({
            "height": at,
            "expected": expected_root,
            "observed": actual_root,
            "status": status,
        })
    return {
        "network": network,
        "target_sha256": TARGET,
        "digest_kind": RAW_KIND,
        "reference": {"origin": reference_origin, "data_sha256": reference_sha},
        "observation": {"origin": observed_origin, "data_sha256": observed_sha},
        "results": results,
    }


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--height", required=True, type=int)
    parser.add_argument("--network", required=True)
    parser.add_argument("--reference", required=True, type=Path)
    parser.add_argument("--observation", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = reconcile(args.height, args.network, args.reference, args.observation)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    print(json.dumps(report, sort_keys=True))
    return 0 if all(result["status"] == "match" for result in report["results"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
