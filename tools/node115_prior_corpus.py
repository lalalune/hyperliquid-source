"""Authenticate the public record snapshot used by blocked #115 comparisons.

The snapshot replaces unavailable private worktree copies. It is a frozen
comparison input set, not a whole-node coverage or ownership denominator.
"""
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re

MANIFEST = "research/work-items/RE-review-open-20261106/prior-source-manifest.json"
MANIFEST_SHA256 = "c84253f3cc24dff04379393266168cd0c5d4ce504cb21ae00390ca483ee32fa3"
RECORD_COUNT = 1210
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
MARKER = "PRIOR_CORPUS %s %d records verified" % (MANIFEST_SHA256, RECORD_COUNT)
_cache = {}


def verify_files(root, entries):
    root = Path(root).resolve()
    found = []
    seen = set()
    for entry in entries:
        name = entry["path"]
        relative = Path(name)
        if (relative.is_absolute() or ".." in relative.parts
                or not name.startswith("research/work-items/")
                or relative.name != "records.json" or name in seen):
            raise ValueError("invalid or duplicate prior record path: " + name)
        seen.add(name)
        path = root / relative
        try:
            path.resolve().relative_to(root)
            raw = path.read_bytes()
        except (OSError, ValueError) as exc:
            raise ValueError("missing prior record: " + name) from exc
        if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise ValueError("prior record digest mismatch: " + name)
        found.append(path)
    return tuple(found)


def _reference(root):
    root = Path(os.environ.get("NODE115_PRIOR_ROOT", str(root))).resolve()
    manifest = root / MANIFEST
    try:
        raw = manifest.read_bytes()
    except OSError as exc:
        raise ValueError("missing pinned public prior corpus") from exc
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise ValueError("prior corpus manifest digest mismatch")
    record = json.loads(raw)
    entries = record["records"]
    if (record.get("schema") != 1 or record.get("target_sha256") != TARGET_SHA256
            or len(entries) != RECORD_COUNT):
        raise ValueError("prior corpus scope mismatch")
    try:
        fingerprint = tuple((entry["path"], (root / entry["path"]).stat().st_size,
                             (root / entry["path"]).stat().st_mtime_ns)
                            for entry in entries)
    except OSError as exc:
        raise ValueError("missing pinned prior record") from exc
    cached = _cache.get(root)
    if cached is None or cached[0] != fingerprint:
        found = verify_files(root, entries)
        _cache[root] = (fingerprint, found)
        print(MARKER)
    return root, _cache[root][1]


def paths(root, pattern="*/records.json"):
    """Return authenticated record paths, or their packet dirs for dir globs."""
    root, found = _reference(root)
    base = root / "research/work-items"
    if pattern.endswith("records.json"):
        return [str(p) for p in found
                if fnmatch.fnmatch(p.relative_to(base).as_posix(), pattern)]
    return sorted({str(p.parent) for p in found
                   if fnmatch.fnmatch(p.parent.relative_to(base).as_posix(), pattern)})


def is_verified(root):
    _reference(root)
    return True


def report_verified(output):
    return MARKER in output


def parse_range(value):
    if isinstance(value, list) and len(value) == 2:
        lo, hi = (int(x, 0) if isinstance(x, str) else int(x) for x in value)
    elif isinstance(value, str):
        match = re.fullmatch(r"\s*(0x[0-9a-fA-F]+)\s*\.\.\s*(0x[0-9a-fA-F]+)(?:\s*\((\d+) bytes\))?\s*", value)
        if not match:
            raise ValueError("unsupported prior range")
        lo, hi = int(match[1], 16), int(match[2], 16)
        if match[3] is not None and int(match[3]) != hi - lo:
            raise ValueError("prior range byte annotation mismatch")
    else:
        raise ValueError("unsupported prior range")
    if lo < 0 or hi <= lo:
        raise ValueError("invalid prior range bounds")
    return lo, hi


def _explicit_ranges(record, inside=False):
    if isinstance(record, dict):
        if inside:
            if "range" in record:
                try:
                    yield parse_range(record["range"])
                except ValueError:
                    pass
            elif "start" in record and "end" in record:
                try:
                    yield parse_range([record["start"], record["end"]])
                except ValueError:
                    pass
        for key, child in record.items():
            if key.startswith(("next", "prev", "cited")) or key in ("survey", "census"):
                continue
            yield from _explicit_ranges(child, inside or key in ("exhibits", "windows"))
    elif isinstance(record, list):
        for child in record:
            yield from _explicit_ranges(child, inside)


def is_documented(root, lo, hi):
    """A former next-work hint can now have a complete, pinned exhibit."""
    _, found = _reference(root)
    for path in found:
        record = json.loads(path.read_bytes())
        if any(a <= lo and hi <= b for a, b in _explicit_ranges(record)):
            return True
    return False
