"""Check retained replay links before the first-conversion Context fixture."""

import hashlib
import json
import subprocess


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(manifest, digest, scratch, compare_links, run_sequence, wire_case, toolkit, cursor, decoder,
        compare_case, helper):
    spec = toolkit["begin"].pinned_json(manifest, digest)
    roles = wire_case.ROLES - {"wire"}
    require(set(spec) == roles | {"height", "restored_round", "ordered_pair", "records"},
            "invalid single retained batch manifest")
    records = spec["records"]
    require(isinstance(records, list) and records, "missing retained batch records")

    staged = []
    for position, entry in enumerate(records):
        require(isinstance(entry, dict) and set(entry) == {"path", "sha256", "prepared_count"},
                f"invalid retained entry {position}")
        raw = (manifest.parent / entry["path"]).read_bytes()
        require(hashlib.sha256(raw).hexdigest() == entry["sha256"], f"wrong row {position} pin")
        artifact = wire_case.save(scratch, f"retained-{position}.bin", raw)
        staged.append({**artifact, "prepared_count": entry["prepared_count"]})

    checks = []
    for prior, current in zip(staged, staged[1:]):
        result = json.loads(subprocess.check_output([
            compare_links.resolve(), scratch / prior["path"], scratch / current["path"],
        ]))
        index = len(checks) + 1
        if result["expected_identity"] != result["observed_identity"]:
            raise ValueError(f"retained identity mismatch at positions {index - 1} -> {index}")
        if result["expected_predecessor"] != result["observed_predecessor"]:
            raise ValueError(f"retained fingerprint mismatch at positions {index - 1} -> {index}")
        require(result["link_matches"], f"inconsistent link audit at position {index}")
        checks.append({
            "previous_index": index - 1, "current_index": index,
            "expected_identity": result["expected_identity"],
            "fingerprint": result["expected_predecessor"],
            "previous_wire_sha256": prior["sha256"], "current_wire_sha256": current["sha256"],
        })

    staged_manifest = {**spec, "records": staged}
    for role in roles:
        source = spec[role]
        require(isinstance(source, dict) and set(source) == {"path", "sha256"}, f"wrong {role} artifact")
        staged_manifest[role] = {**source, "path": str((manifest.parent / source["path"]).resolve())}
    saved = wire_case.save_json(scratch, "linked-sequence.json", staged_manifest)
    projected = run_sequence(scratch / saved["path"], saved["sha256"], scratch,
                             wire_case, toolkit, cursor, decoder, compare_case, helper)
    return {"verified_retained_links": checks, **projected}
