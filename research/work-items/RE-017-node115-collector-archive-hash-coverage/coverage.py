"""Check a pinned replay observation against a complete archive response Hash."""

import hashlib


def check(manifest, pin, audit, compare, codec):
    require = audit.require
    raw = manifest.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == pin, "wrong fixture SHA-256")
    spec = audit.load(raw)
    require(type(spec) is dict and set(spec) == {"checkpoint_height", "archive", "observation"}, "wrong fixture roles")
    for name in ("archive", "observation"):
        require(type(spec[name]) is dict and set(spec[name]) == {"path", "sha256"}, f"wrong {name} artifact")
    archive_raw = audit.artifact(manifest.parent, spec["archive"])
    require(archive_raw.endswith(b"\n") and archive_raw.count(b"\n") == 1, "expected one original archive row")
    archive = audit.load(archive_raw)
    observation = audit.load(audit.artifact(manifest.parent, spec["observation"]))
    require(type(observation) is dict and set(observation) == {"height", "ordinals", "stop_position", "resps"},
            "wrong collector observation roles")
    successor = audit.u64(spec["checkpoint_height"], "checkpoint height") + 1
    for name, fixture in (("archive", archive), ("collector", observation)):
        require(audit.u64(fixture["height"], name + " height") == successor, f"{name} is not at H+1")
    result = archive["resps"]
    require(type(result) is dict and set(result) == {"Hash"}, "expected archive response Hash")
    expected = codec.fixed_hex(result["Hash"], 32).decode("ascii")
    full = observation["resps"]
    require(type(full) is dict and set(full) == {"Full"}, "expected collector Full response")
    observed = audit.indexed(full["Full"], "observed Full")
    ordinals = observation["ordinals"]
    require(type(ordinals) is list and len(ordinals) == len(observed), "wrong collector ordinal count")
    source_positions = [audit.u64(value, "source ordinal") for value in ordinals]
    require(len(set(source_positions)) == len(source_positions), "collector ordinals repeat")
    stop = observation["stop_position"]
    require(stop is None or audit.u64(stop, "stop position") == len(observed), "wrong collector stop position")

    geometry = audit.indexed(archive["abci_block"]["signed_action_bundles"], "archive signed bundles")
    size = {}
    for key, body in geometry.items():
        require(type(body) is dict and type(body["signed_actions"]) is list, f"wrong signed bundle {key}")
        size[key] = len(body["signed_actions"])
    require(observed.keys() <= size.keys(), "collector references a key outside archived geometry")
    for key, entries in observed.items():
        require(type(entries) is list and size[key] == len(entries), f"action count differs for {key}")
    missing = [key for key in size if key not in observed]

    computed = None if missing else compare(archive, observation, codec)
    return {
        "height": successor,
        "archive_sha256": spec["archive"]["sha256"],
        "observation_sha256": spec["observation"]["sha256"],
        "collector_order": [{"key": key, "source_ordinal": source} for key, source in zip(observed, source_positions)],
        "missing_archive_keys": missing,
        "stop_position": stop,
        "expected": expected,
        "actual": None if computed is None else computed.actual,
        "matches": None if computed is None else computed.matches,
    }
