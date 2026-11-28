"""Feed verified prefilter attachment counts into first-converted offline replay."""

import hashlib
import json
import subprocess


def require(condition, text):
    if not condition:
        raise ValueError(text)


def run(manifest, digest, scratch, operations):
    attachment_probe, audit_archive, first_converted, wire_case, kit, *rest = operations
    spec = kit["begin"].pinned_json(manifest, digest)
    roles = wire_case.ROLES - {"wire"}
    required = {"height", "restored_round", "ordered_pair", "records", "successful_rows"} | roles
    require(set(spec) == required, "wrong prefilter conversion fixture roles")
    raw_records = spec["records"]
    require(isinstance(raw_records, list) and raw_records, "expected pinned original source owners")
    records = []
    for index, artifact in enumerate(raw_records):
        require(isinstance(artifact, dict) and set(artifact) == {"path", "sha256"},
                f"wrong source row declaration {index}")
        raw = (manifest.parent / artifact["path"]).read_bytes()
        require(hashlib.sha256(raw).hexdigest() == artifact["sha256"], f"wrong capture SHA-256 at {index}")
        keys = subprocess.check_output([attachment_probe.resolve()], input=raw).splitlines()
        staged = wire_case.save(scratch, f"prefilter-row-{index}.bin", raw)
        records.append({**staged, "prepared_count": len(keys)})

    scoped = {key: spec[key] for key in ("height", "restored_round", "ordered_pair")}
    scoped["records"] = records
    for role in roles:
        artifact = spec[role]
        require(isinstance(artifact, dict) and set(artifact) == {"path", "sha256"}, f"wrong {role} artifact")
        scoped[role] = {**artifact, "path": str((manifest.parent / artifact["path"]).resolve())}
    case = wire_case.save_json(scratch, "measured-prefilter-counts.json", scoped)
    compared = first_converted(scratch / case["path"], case["sha256"], scratch, wire_case, kit, *rest)
    selected = compared["cursor"][-1]
    index = selected["index"]
    audit_case = wire_case.save_json(scratch, "converted-archive-keys.json", {
        "height": compared["selected_wire_header"]["height"],
        "wire": {key: records[index][key] for key in ("path", "sha256")},
        "archive": scoped["archive"], "successful_rows": spec["successful_rows"],
    })
    audit = audit_archive(scratch / audit_case["path"], audit_case["sha256"], attachment_probe)
    require(audit["verified_source_count"] == selected["prepared_count"], "changed source owner geometry")
    return {"prefilter_count": selected["prepared_count"], "archive_output_count": len(audit["archived_keys"]),
            "archive_keys": audit, **compared}
