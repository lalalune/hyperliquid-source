"""Preserve supplied native retained batch boundaries through one converter cursor."""

import hashlib
import json
import subprocess


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(manifest, digest, scratch, operations):
    link_probe, sequence, wire_case, kit, *rest = operations
    begin = kit["begin"]
    spec = begin.pinned_json(manifest, digest)
    roles = wire_case.ROLES - {"wire"}
    require(set(spec) == roles | {"height", "restored_round", "ordered_pair", "batches"}, "wrong replay roles")
    groups = spec["batches"]
    require(isinstance(groups, list) and groups, "expected observed retained batch groups")
    records, starts, links = [], [], []
    for batch, group in enumerate(groups):
        require(isinstance(group, dict) and set(group) == {"baseline", "records"}, f"bad batch {batch}")
        initial = begin.u64(group["baseline"], f"batch {batch} observed publication baseline")
        items = group["records"]
        require(isinstance(items, list) and items, f"empty retained batch {batch}")
        starts.append({"batch": batch, "position": len(records), "baseline": initial})
        prior = None
        for index, record in enumerate(items):
            require(isinstance(record, dict) and set(record) == {"path", "sha256", "prepared_count"},
                    f"bad retained batch {batch} row {index}")
            raw = (manifest.parent / record["path"]).read_bytes()
            require(hashlib.sha256(raw).hexdigest() == record["sha256"], f"wrong retained row {batch}/{index} pin")
            current = wire_case.save(scratch, f"batch-{batch}-row-{index}.bin", raw)
            if prior is not None:
                link = json.loads(subprocess.check_output([link_probe, scratch / prior["path"],
                                                         scratch / current["path"]]))
                require(link["link_matches"], f"same-batch identity or fingerprint mismatch at {batch}/{index}")
                links.append({"batch": batch, "previous": index - 1, "current": index,
                              "identity": link["observed_identity"], "fingerprint": link["observed_predecessor"]})
            records.append({**current, "prepared_count": record["prepared_count"]})
            prior = current

    flattened = {key: spec[key] for key in ("height", "restored_round", "ordered_pair")}
    flattened["records"] = records
    for role in roles:
        item = spec[role]
        require(isinstance(item, dict) and set(item) == {"path", "sha256"}, f"bad {role} artifact")
        flattened[role] = {**item, "path": str((manifest.parent / item["path"]).resolve())}
    staged = wire_case.save_json(scratch, "batch-bounded-first-conversion.json", flattened)
    result = sequence(scratch / staged["path"], staged["sha256"], scratch, wire_case, kit, *rest)
    events = result["cursor"]
    for start in starts:
        position = start["position"]
        start["checked_before_conversion"] = position < len(events)
        if start["checked_before_conversion"]:
            expected = spec["restored_round"] if position == 0 else events[position - 1]["expected_after"]
            require(start["baseline"] == expected == events[position]["identity"],
                    f"observed baseline disagrees with cursor at batch {start['batch']}")
    return {"retained_batches": starts, "checked_same_batch_links": links, **result}
