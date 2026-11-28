"""Select the first converted record before running adjacent Context checks."""

import hashlib
import json
import subprocess


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(manifest, sha256, scratch, wire_case, kit, cursor, probe, compare_case, helper):
    begin = kit["begin"]
    data = begin.pinned_json(manifest, sha256)
    roles = wire_case.ROLES - {"wire"}
    require(set(data) == roles | {"height", "restored_round", "ordered_pair", "records"},
            "wrong sequence fixture roles")
    initial = begin.u64(data["restored_round"], "selected restored consensus round")
    height = begin.u64(data["height"], "checkpoint height")
    checkpoint = data["checkpoint_rmp"]
    require(isinstance(checkpoint, dict) and set(checkpoint) == {"path", "sha256"},
            "invalid checkpoint artifact")
    restored = kit["messagepack"].project_rmp(
        manifest.parent / checkpoint["path"], checkpoint["sha256"], height, kit["normalizer"],
    )
    require(restored["round"] == initial, "ordinary restored round differs from checkpoint round")
    records = data["records"]
    require(isinstance(records, list) and bool(records), "empty capture sequence")
    operands = [cursor.resolve(), str(initial)]
    pinned = []
    for index, record in enumerate(records):
        require(isinstance(record, dict) and set(record) == {"path", "sha256", "prepared_count"},
                f"record {index} needs path, SHA-256 and independent prepared count")
        raw = (manifest.parent / record["path"]).read_bytes()
        require(hashlib.sha256(raw).hexdigest() == record["sha256"], f"record {index} SHA-256 mismatch")
        saved = wire_case.save(scratch, f"captured-{index}.bin", raw)
        pinned.append(saved)
        count = begin.u64(record["prepared_count"], "prepared owner input count")
        operands += [scratch / saved["path"], str(count)]

    output = subprocess.check_output(operands).splitlines()
    trace = [json.loads(line) for line in output]
    require(bool(trace), "cursor returned no observations")
    for index, event in enumerate(trace):
        require(event["index"] == index and index < len(records), "cursor trace is out of order")
        event["wire_sha256"] = pinned[index]["sha256"]
    selected = trace[-1]
    require(selected["outcome"] != "identity_mismatch",
            f"cursor identity mismatch before conversion at record {selected['index']}")
    require(selected["outcome"] == "converted", "captured sequence ends before the first conversion")

    adapted = {"height": data["height"], "ordered_pair": data["ordered_pair"],
               "conversion_cutoff": selected["parent_round"], "wire": pinned[selected["index"]]}
    for role in roles:
        artifact = data[role]
        require(isinstance(artifact, dict) and set(artifact) == {"path", "sha256"}, f"invalid {role} artifact")
        adapted[role] = {**artifact, "path": str((manifest.parent / artifact["path"]).resolve())}
    entry = wire_case.save_json(scratch, "cursor-selected-case.json", adapted)
    case, digest, header = wire_case.export_case(scratch / entry["path"], entry["sha256"], kit, probe, scratch)
    require(header["round"] == selected["successor"], "runner disagrees with cursor successor")
    return {"cursor": trace, "selected_wire_header": header,
            "selected_root_comparison": compare_case(case, digest, kit, helper)}
