"""Build a lossless Block-only fixture view of a pinned mixed offline capture."""

import hashlib
import json
import subprocess


def require(condition, text):
    if not condition:
        raise ValueError(text)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def run(manifest, manifest_sha, scratch, mixed_probe, ordinary, ordinary_ops):
    wire_case, kit = ordinary_ops[2][2:4]
    spec = kit["begin"].pinned_json(manifest, manifest_sha)
    source = spec["framed_capture"]
    require(isinstance(source, dict) and set(source) == {"path", "sha256", "frames"},
            "expected framed capture path, SHA-256 and independent frame metadata")
    original = (manifest.parent / source["path"]).read_bytes()
    require(digest(original) == source["sha256"], "wrong mixed capture SHA-256")
    source_path = scratch / "mixed-source.bin"
    source_path.write_bytes(original)
    output = scratch / "mixed-payloads"
    output.mkdir(exist_ok=True)
    events = [json.loads(line) for line in subprocess.check_output(
        [mixed_probe, source_path, output],
    ).splitlines()]
    expected = source["frames"]
    require(type(expected) is list and bool(expected) and len(expected) == len(events),
            "wrong mixed frame inventory size")

    offset = 0
    kept, block_frames, receipts = [], [], []
    for index, (item, event) in enumerate(zip(expected, events)):
        require(isinstance(item, dict)
                and set(item) == {"kind", "frame_sha256", "payload_sha256", "prepared_count"},
                f"wrong mixed frame declaration at {index}")
        require(event["index"] == index and event["offset"] == offset and event["frame_size"] >= 5,
                f"wrong frame geometry at {index}")
        end = offset + event["frame_size"]
        require(end <= len(original), f"frame {index} exceeds the capture")
        frame = original[offset:end]
        payload = (output / f"payload-{index}.bin").read_bytes()
        require(digest(frame) == item["frame_sha256"] and digest(payload) == item["payload_sha256"]
                and len(payload) == event["payload_size"], f"wrong frame or payload pin at {index}")
        require(event["kind"] == item["kind"] and event["kind"] in ("Tx", "Block"),
                f"wrong decoded frame kind at {index}")
        event["frame_sha256"] = item["frame_sha256"]
        event["payload_sha256"] = item["payload_sha256"]
        event["block_view_index"] = None
        if event["kind"] == "Block":
            kit["begin"].u64(item["prepared_count"], "observed prepared count")
            event["block_view_index"] = len(kept)
            kept.append(frame)
            block_frames.append({key: item[key] for key in ("frame_sha256", "payload_sha256", "prepared_count")})
        else:
            require(item["prepared_count"] is None, f"Tx frame {index} has no prepared Block count")
        receipts.append(event)
        offset = end
    require(offset == len(original), "mixed capture has unrepresented bytes")
    require(bool(kept), "mixed capture contains no Block frames")

    derived = wire_case.save(scratch, "block-view.bin", b"".join(kept))
    copied = {**spec, "framed_capture": {**derived, "frames": block_frames}}
    for role in wire_case.ROLES - {"wire"}:
        entry = spec[role]
        require(type(entry) is dict and set(entry) == {"path", "sha256"}, f"invalid {role} artifact")
        copied[role] = {**entry, "path": str((manifest.parent / entry["path"]).resolve())}
    fixture = wire_case.save_json(scratch, "mixed-block-view.json", copied)
    checked = ordinary(scratch / fixture["path"], fixture["sha256"], scratch, *ordinary_ops)
    return {"mixed_capture_sha256": source["sha256"], "source_frame_receipts": receipts,
            "derived_block_view": checked}
