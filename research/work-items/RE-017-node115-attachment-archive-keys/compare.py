"""Compare the archive bundle keys with successful source row observations."""

from argparse import ArgumentParser
import hashlib
import json
from pathlib import Path
import re
import subprocess

KEY = re.compile(r"0x[0-9a-f]{64}")


def require(condition, text):
    if not condition:
        raise ValueError(text)


def unique(fields):
    value = dict(fields)
    require(len(value) == len(fields), "duplicate JSON key")
    return value


def raw_json(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique)


def pinned(folder, item):
    require(type(item) is dict and set(item) == {"path", "sha256"}, "wrong artifact schema")
    raw = (folder / item["path"]).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == item["sha256"], f"wrong {item['path']} SHA-256")
    return raw


def compare(manifest, manifest_sha, probe):
    raw = manifest.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == manifest_sha, "wrong manifest SHA-256")
    spec = raw_json(raw)
    require(set(spec) == {"height", "wire", "archive", "successful_rows"}, "wrong case roles")
    wire = pinned(manifest.parent, spec["wire"])
    line = pinned(manifest.parent, spec["archive"])
    require(line.endswith(b"\n") and line.count(b"\n") == 1, "expected one complete original archive line")
    archive = raw_json(line)
    height = spec["height"]
    require(type(height) is int and 0 <= height < 1 << 64 and
            type(archive["height"]) is int and height == archive["height"], "archive height mismatch")
    attachment_keys = subprocess.check_output([probe.resolve()], input=wire, text=False).decode("ascii").splitlines()
    require(all(KEY.fullmatch(key) for key in attachment_keys), "bad decoded key width")
    selected = spec["successful_rows"]
    require(type(selected) is list and all(type(i) is int and 0 <= i < len(attachment_keys) for i in selected),
            "successful row lies outside verified source owner")
    require(all(a < b for a, b in zip(selected, selected[1:])), "success positions must preserve source order")
    rows = archive["abci_block"]["signed_action_bundles"]
    require(type(rows) is list, "expected native bundle array")
    observed = []
    for row in rows:
        require(type(row) is list and len(row) == 2 and type(row[0]) is str and KEY.fullmatch(row[0]),
                "wrong archive bundle key")
        observed.append(row[0])
    expected = [attachment_keys[index] for index in selected]
    return {"height": height, "verified_source_count": len(attachment_keys), "observed_success_positions": selected,
            "expected_archive_keys": expected, "archived_keys": observed, "matched": expected == observed}


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("manifest_sha256")
    parser.add_argument("probe", type=Path)
    args = parser.parse_args()
    try:
        result = compare(args.manifest, args.manifest_sha256, args.probe)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print(json.dumps(result))
    raise SystemExit(0 if result["matched"] else 1)
