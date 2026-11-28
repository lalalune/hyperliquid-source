"""Verify transport frame and decoded replay-byte custody before offline checks."""

import hashlib
import json
import subprocess


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def run(manifest, digest, scratch, frame_probe, linked, linked_ops):
    wire_case, kit = linked_ops[2:4]
    begin = kit["begin"]
    case = begin.pinned_json(manifest, digest)
    external = (wire_case.ROLES - {"wire"}) | {"height", "restored_round", "ordered_pair", "framed_capture"}
    require(set(case) == external, "wrong retained frame fixture roles")
    source = case["framed_capture"]
    require(isinstance(source, dict) and set(source) == {"path", "sha256", "frames"},
            "wrong framed capture declaration")
    captured = (manifest.parent / source["path"]).read_bytes()
    require(sha(captured) == source["sha256"], "wrong original frame-stream SHA-256")
    original = wire_case.save(scratch, "raw-frame-stream.bin", captured)
    declared = source["frames"]
    require(isinstance(declared, list) and declared, "expected independently observed frame metadata")
    payload_dir = scratch / "frame-payloads"
    payload_dir.mkdir(exist_ok=True)
    report = subprocess.check_output([frame_probe, scratch / original["path"], payload_dir])
    observed = [json.loads(line) for line in report.splitlines()]
    require(len(declared) == len(observed), "capture frame count differs from supplied references")

    offset = 0
    records = []
    for index, (actual, expected) in enumerate(zip(observed, declared)):
        require(isinstance(expected, dict)
                and set(expected) == {"frame_sha256", "payload_sha256", "prepared_count"},
                f"invalid external frame reference {index}")
        require(actual["index"] == index and actual["offset"] == offset and actual["frame_size"] >= 5,
                f"wrong frame boundary at {index}")
        offset += actual["frame_size"]
        require(offset <= len(captured), "frame extent exceeds captured bytes")
        wire = captured[actual["offset"]:offset]
        require(sha(wire) == expected["frame_sha256"], f"wrong source frame SHA-256 at {index}")
        payload_path = payload_dir / f"payload-{index}.bin"
        payload = payload_path.read_bytes()
        payload_sha = sha(payload)
        require(actual["payload_size"] == len(payload) and payload_sha == expected["payload_sha256"],
                f"wrong decoded payload SHA-256 at {index}")
        actual["frame_sha256"] = expected["frame_sha256"]
        actual["payload_sha256"] = payload_sha
        records.append({"path": str(payload_path), "sha256": payload_sha, "prepared_count": expected["prepared_count"]})
    require(offset == len(captured), "frame intervals do not cover the complete capture")

    mapped = {key: case[key] for key in external - {"framed_capture"}}
    mapped["records"] = records
    for role in wire_case.ROLES - {"wire"}:
        item = case[role]
        require(isinstance(item, dict) and set(item) == {"path", "sha256"}, f"bad {role} artifact")
        mapped[role] = {**item, "path": str((manifest.parent / item["path"]).resolve())}
    projected = wire_case.save_json(scratch, "frame-preserved-case.json", mapped)
    checked = linked(scratch / projected["path"], projected["sha256"], scratch, *linked_ops)
    return {"capture_sha256": original["sha256"], "frame_receipts": observed, **checked}
