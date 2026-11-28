"""Match selected opaque store entries to separately pinned raw attachment bodies."""

import json


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(manifest, digest, scratch, output, ring, tree, sidecar):
    ring_measure, ring_probe = ring
    tree_resolve, tree_probe = tree
    spec_data = manifest.read_bytes()
    require(sidecar.sha(spec_data) == digest, "wrong manifest SHA-256")
    spec = json.loads(spec_data, object_pairs_hook=sidecar.unique)
    require(isinstance(spec, dict) and set(spec) == {"wire", "store", "bodies"}, "wrong owner fixture roles")
    wire, store = spec["wire"], spec["store"]
    require(isinstance(wire, dict) and set(wire) == {"path", "sha256"}, "wrong wire artifact")
    require(isinstance(store, dict) and set(store) == {"kind", "path", "sha256"}, "wrong store observation")
    wire_path, store_path = (manifest.parent / artifact["path"] for artifact in (wire, store))
    if store["kind"] == "ring":
        resolution = ring_measure(ring_probe, scratch, wire_path, wire["sha256"], store_path, store["sha256"])
    elif store["kind"] == "tree":
        resolution = tree_resolve(wire_path, wire["sha256"], store_path, store["sha256"], tree_probe)
    else:
        raise ValueError("expected a native ring or tree observation")
    if resolution["status"] == "missing":
        return {"store_kind": store["kind"], "resolution": resolution, "body_custody": None}
    require(resolution["status"] == "materialized", "wrong resolved store result")

    catalog = {}
    require(isinstance(spec["bodies"], list), "wrong raw-body catalog")
    for entry in spec["bodies"]:
        require(isinstance(entry, dict) and set(entry) == {"id", "path", "sha256"}, "wrong body entry")
        identifier = entry["id"]
        require(type(identifier) is int and 0 < identifier < 1 << 64 and identifier not in catalog,
                "wrong or duplicate opaque identifier")
        catalog[identifier] = {"path": str((manifest.parent / entry["path"]).resolve()), "sha256": entry["sha256"]}
    objects = {}
    for row in resolution["rows"]:
        identifier = row["opaque_value"]
        require(identifier in catalog, f"selected opaque identifier {identifier} has no body")
        key = "0x" + row["key"].removeprefix("0x")
        entry = {**catalog[identifier], "keccak256": key}
        require(key not in objects or objects[key] == entry, "inconsistent raw objects for a repeated key")
        objects[key] = entry

    scoped = {
        "wire": {**wire, "path": str(wire_path.resolve())},
        "objects": list(objects.values()),
    }
    destination = scratch / "derived-object-manifest.json"
    raw = json.dumps(scoped).encode()
    destination.write_bytes(raw)
    custody = sidecar.stage(destination, sidecar.sha(raw), tree_probe, output)
    resolved_keys = ["0x" + row["key"].removeprefix("0x") for row in resolution["rows"]]
    require([row["content_key"] for row in custody["derived_rows"]] == resolved_keys,
            "body custody output differs from the native lookup order")
    return {"store_kind": store["kind"], "resolution": resolution, "body_custody": custody}
