"""Stage separately acquired raw attachment bodies in decoded header order."""

import hashlib
import json
import re
import subprocess

from Crypto.Hash import keccak

KEY = re.compile(r"0x[0-9a-f]{64}")


def require(condition, text):
    if not condition:
        raise ValueError(text)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(entries):
    result = dict(entries)
    require(len(result) == len(entries), "duplicate manifest field")
    return result


def stage(manifest, digest, probe, output):
    raw_spec = manifest.read_bytes()
    require(sha(raw_spec) == digest, "wrong attachment manifest SHA-256")
    spec = json.loads(raw_spec, object_pairs_hook=unique)
    require(isinstance(spec, dict) and set(spec) == {"wire", "objects"}, "wrong attachment manifest roles")
    wire = spec["wire"]
    require(isinstance(wire, dict) and set(wire) == {"path", "sha256"}, "wrong wire artifact")
    raw = (manifest.parent / wire["path"]).read_bytes()
    require(sha(raw) == wire["sha256"], "wrong original wire SHA-256")
    probe_rows = subprocess.check_output([probe.resolve()], input=raw).decode("ascii").splitlines()
    marker, *needed = probe_rows
    require(marker == "absent", "decoded Block already carries an attachment owner")
    require(all(KEY.fullmatch(key) for key in needed), "wrong decoded attachment key")
    require(isinstance(spec["objects"], list), "expected raw attachment object list")
    objects = {}
    for item in spec["objects"]:
        require(isinstance(item, dict) and set(item) == {"path", "sha256", "keccak256"},
                "wrong raw attachment entry")
        key = item["keccak256"]
        require(isinstance(key, str) and KEY.fullmatch(key) and key not in objects,
                "invalid or duplicate raw attachment key")
        objects[key] = item

    supplied = {}
    for key in dict.fromkeys(needed):
        require(key in objects, f"missing independently supplied attachment {key}")
        artifact = objects[key]
        contents = (manifest.parent / artifact["path"]).read_bytes()
        require(sha(contents) == artifact["sha256"], f"raw attachment SHA-256 mismatch {key}")
        actual = "0x" + keccak.new(digest_bits=256, data=contents).hexdigest()
        require(actual == key, f"raw attachment differs from decoded key {key}")
        supplied[key] = contents

    output.mkdir()
    report = {"source_wire_sha256": wire["sha256"], "wire_attachment_owner": marker, "derived_rows": []}
    for index, key in enumerate(needed):
        artifact = objects[key]
        name = f"attachment-{index}.bin"
        (output / name).write_bytes(supplied[key])
        report["derived_rows"].append({
            "index": index, "content_key": key, "path": name, "sha256": artifact["sha256"],
            "source_path": artifact["path"], "bytes": len(supplied[key]),
        })
    return report
