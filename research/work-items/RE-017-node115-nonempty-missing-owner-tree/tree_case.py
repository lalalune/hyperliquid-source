"""Resolve an omitted replay owner from a pinned ordinary tree observation."""

import hashlib
import json
import re
import subprocess

KEY = re.compile(r"0x[0-9a-f]{64}")


def require(condition, text):
    if not condition:
        raise ValueError(text)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    row = dict(pairs)
    require(len(row) == len(pairs), "duplicate JSON member")
    return row


def read(path, expected):
    raw = path.read_bytes()
    require(sha(raw) == expected, f"wrong SHA-256 for {path.name}")
    return raw


def inspect(node, depth, lower=None, upper=None):
    require(isinstance(node, dict) and set(node) == {"entries", "children"}, "invalid tree node")
    entries, children = node["entries"], node["children"]
    require(type(entries) is list and 0 < len(entries) <= 11 and type(children) is list,
            "expected ordinary native node capacity")
    previous = lower
    keys = []
    for row in entries:
        require(type(row) is list and len(row) == 2, "expected tree key and opaque identifier")
        key, item = row
        require(type(key) is str and KEY.fullmatch(key) and (previous is None or previous < key)
                and (upper is None or key < upper), "out-of-order tree key")
        require(type(item) is int and 0 < item < (1 << 64), "invalid opaque identifier")
        previous = key
        keys.append(key)
    require(len(children) == (0 if depth == 0 else len(entries) + 1), "wrong child count for supplied depth")
    padded = [lower, *keys, upper]
    for child, lo, hi in zip(children, padded, padded[1:]):
        inspect(child, depth - 1, lo, hi)


def lookup(root, query):
    node = root
    path = []
    while True:
        slot = 0
        for key, value in node["entries"]:
            if key == query:
                return {"child_path": path, "slot": slot, "opaque_value": value}
            if query < key:
                break
            slot += 1
        if not node["children"]:
            return None
        node = node["children"][slot]
        path.append(slot)


def resolve(wire, wire_sha, fixture, fixture_sha, probe):
    captured = read(wire, wire_sha)
    store = json.loads(read(fixture, fixture_sha), object_pairs_hook=unique)
    require(isinstance(store, dict) and set(store) == {"depth", "root"}, "bad observed tree")
    depth = store["depth"]
    require(type(depth) is int and depth >= 0, "invalid observed depth")
    inspect(store["root"], depth)
    owner, *keys = subprocess.check_output([probe], input=captured).decode("ascii").splitlines()
    require(owner == "absent" and keys and all(KEY.fullmatch(key) for key in keys),
            "expected omitted owner with a nonempty decoded key vector")
    output = {"wire_sha256": wire_sha, "tree_sha256": fixture_sha}
    resolved = []
    for index, key in enumerate(keys):
        row = lookup(store["root"], key)
        if row is None:
            return {**output, "status": "missing", "position": index, "key": key}
        resolved.append({"position": index, "key": key, **row})
    return {**output, "status": "materialized", "rows": resolved}
