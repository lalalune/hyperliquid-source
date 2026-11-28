"""Keep physical capture-fragment provenance through verified offline replay."""

from bisect import bisect_right
import hashlib


def require(condition, text):
    if not condition:
        raise ValueError(text)


def assembled(folder, entries, destination, expected):
    require(type(entries) is list and entries, "expected ordered source fragments")
    aggregate = hashlib.sha256()
    layouts = []
    offset = 0
    with destination.open("wb") as output:
        for number, entry in enumerate(entries):
            require(isinstance(entry, dict) and set(entry) == {"path", "sha256"},
                    f"bad capture fragment {number}")
            partial = hashlib.sha256()
            size = 0
            with (folder / entry["path"]).open("rb") as source:
                for block in iter(lambda: source.read(65536), b""):
                    partial.update(block)
                    aggregate.update(block)
                    output.write(block)
                    size += len(block)
            require(partial.hexdigest() == entry["sha256"], f"wrong capture-fragment SHA-256 at {number}")
            layouts.append({"fragment": number, "path": entry["path"],
                            "sha256": entry["sha256"], "start": offset, "size": size})
            offset += size
    require(aggregate.hexdigest() == expected, "wrong joined frame-stream SHA-256")
    return layouts, offset


def slices(frame, fragments, starts):
    start, size = frame["offset"], frame["frame_size"]
    end = start + size
    parts = []
    first = bisect_right(starts, start) - 1
    for index in range(first, len(fragments)):
        fragment = fragments[index]
        if fragment["start"] >= end:
            break
        lo = max(start, fragment["start"])
        hi = min(end, fragment["start"] + fragment["size"])
        if lo < hi:
            parts.append({"fragment": fragment["fragment"], "offset": lo - fragment["start"],
                          "size": hi - lo})
    require(sum(part["size"] for part in parts) == size, "frame crosses an unmapped source byte")
    return parts


def run(manifest, digest, scratch, single_capture, operations):
    wire_case, kit = operations[2][2:4]
    begin = kit["begin"]
    spec = begin.pinned_json(manifest, digest)
    source = spec["framed_capture"]
    require(isinstance(source, dict) and set(source) == {"fragments", "sha256", "frames"},
            "wrong fragmented-capture roles")
    compacted = scratch / "joined-original-fragments.bin"
    layout, size = assembled(manifest.parent, source["fragments"], compacted, source["sha256"])
    fixture = {**spec, "framed_capture": {
        "path": compacted.name, "sha256": source["sha256"], "frames": source["frames"],
    }}
    for role in wire_case.ROLES - {"wire"}:
        entry = spec[role]
        require(isinstance(entry, dict) and set(entry) == {"path", "sha256"}, f"bad {role} artifact")
        fixture[role] = {**entry, "path": str((manifest.parent / entry["path"]).resolve())}
    entry = wire_case.save_json(scratch, "verified-assembled-capture.json", fixture)
    result = single_capture(scratch / entry["path"], entry["sha256"], scratch, *operations)
    receipts = result["frame_receipts"]
    starts = [fragment["start"] for fragment in layout]
    coordinates = []
    next_offset = 0
    for frame in receipts:
        require(frame["offset"] == next_offset, "frame offset differs from complete joined stream")
        coordinates.append({"frame": frame["index"], "parts": slices(frame, layout, starts)})
        next_offset += frame["frame_size"]
    require(next_offset == size, "frame receipts do not cover the complete fragment set")
    return {"source_fragments": layout, "frame_source_ranges": coordinates, **result}
