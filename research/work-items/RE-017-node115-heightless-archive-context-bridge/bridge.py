"""Bind one heightless archive row to a separately identified replay checkpoint."""

import hashlib
import json


def require(condition, message):
    if not condition:
        raise ValueError(message)


def select(shard, expected_digest, chunk_start, height, row_sha256, successor, unsigned):
    require(unsigned(chunk_start) and unsigned(height), "invalid shard or checkpoint coordinate")
    index = height - chunk_start + 1
    offset = 0
    row_offset = None
    with shard.open("rb") as handle:
        def lines():
            nonlocal offset, row_offset
            for number, line in enumerate(handle, 1):
                if number == index:
                    row_offset = offset
                offset += len(line)
                yield line

        row = successor(lines(), chunk_start, height, expected_digest)
    require(row_offset is not None, "archive selector returned no physical coordinate")
    actual = hashlib.sha256(row).hexdigest()
    require(actual == row_sha256, "selected archive row SHA-256 mismatch")
    return row, {
        "addressing": "chunk_start+line_index+1",
        "height": height + 1,
        "chunk_start": chunk_start,
        "line_number": index,
        "byte_offset": row_offset,
        "byte_length": len(row),
        "shard_sha256": expected_digest,
        "row_sha256": actual,
    }


def run(manifest, digest, scratch, selector, wire_case, kit, probe, compare_case, helper):
    begin = kit["begin"]
    spec = begin.pinned_json(manifest, digest)
    ordinary = (wire_case.ROLES - {"archive"}) | {"height", "conversion_cutoff", "ordered_pair"}
    require(set(spec) == ordinary | {"archive_shard"}, "wrong heightless fixture roles")
    source = spec["archive_shard"]
    require(isinstance(source, dict)
            and set(source) == {"path", "sha256", "chunk_start", "row_sha256"},
            "bad archive shard declaration")
    shard = manifest.parent / source["path"]
    raw, origin = select(shard, source["sha256"], source["chunk_start"], spec["height"],
                         source["row_sha256"], selector.successor, selector.unsigned)
    source_row = json.loads(raw)
    block = source_row["abci_block"]
    origin["source_row_has_explicit_height"] = "height" in source_row
    projection = {
        "height": origin["height"],
        "abci_block": {field: block[field] for field in ("time", "round", "parent_round")},
    }
    symbols = {key: spec[key] for key in ordinary}
    for key in wire_case.ROLES - {"archive"}:
        artifact = symbols[key]
        require(isinstance(artifact, dict) and set(artifact) == {"path", "sha256"},
                f"bad {key} artifact declaration")
        symbols[key] = {**artifact, "path": str((manifest.parent / artifact["path"]).resolve())}
    entry = wire_case.save_json(scratch, "projected-archive-header.jsonl", projection)
    symbols["archive"] = entry
    adapted = wire_case.save_json(scratch, "case-explicit-projection.json", symbols)
    accept, accept_sha, header = wire_case.export_case(
        scratch / adapted["path"], adapted["sha256"], kit, probe, scratch,
    )
    return {
        "source_archive": origin,
        "projected_archive_header_sha256": entry["sha256"],
        "wire_derived_successor": header,
        "selected_root_comparison": compare_case(accept, accept_sha, kit, helper),
    }
