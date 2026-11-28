"""Derive the normalized H+1 header from offline replay bytes for Context comparison."""

from datetime import date, timedelta
import hashlib
import json
import subprocess

ROLES = {"wire", "archive", "checkpoint_rmp", "reference_h", "reference_h_plus_one"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def save(folder, name, data):
    (folder / name).write_bytes(data)
    return {"path": name, "sha256": hashlib.sha256(data).hexdigest()}


def save_json(folder, name, values):
    return save(folder, name, (json.dumps(values) + "\n").encode())


def normalized_clock(row):
    nominal = row["date_word"]
    signed = nominal - (1 << 32) if nominal >= (1 << 31) else nominal
    year = signed >> 13
    ordinal = (nominal >> 4) & 0x1ff
    require(1 <= year <= 9999 and ordinal > 0, "unsupported ordinary calendar date")
    day = date(year, 1, 1) + timedelta(days=ordinal - 1)
    require(day.year == year, "packed ordinal outside the year")
    seconds, nanos = row["seconds"], row["nanos"]
    require(0 <= seconds < 86400 and 0 <= nanos < 1_000_000_000, "expected ordinary subday words")
    return {
        "unix_seconds": (day - date(1970, 1, 1)).days * 86400 + seconds,
        "subsec_nanos": nanos,
    }


def export_case(manifest, case_sha, toolkit, probe, scratch):
    begin = toolkit["begin"]
    spec = begin.pinned_json(manifest, case_sha)
    require(set(spec) == {"height", "conversion_cutoff", "ordered_pair", *ROLES}, "wrong fixture roles")
    height = begin.u64(spec["height"], "checkpoint height")
    require(height != (1 << 64) - 1, "height H+1 is not representable")
    cutoff = begin.u64(spec["conversion_cutoff"], "conversion cutoff")
    pair = spec["ordered_pair"]
    require(type(pair) is list and len(pair) == 2, "expected two ordered identity words")
    pair = [begin.u64(word, "identity word") for word in pair]

    def read(role):
        entry = spec[role]
        require(type(entry) is dict and set(entry) == {"path", "sha256"}, f"wrong {role} artifact entry")
        raw = (manifest.parent / entry["path"]).read_bytes()
        require(hashlib.sha256(raw).hexdigest() == entry["sha256"], f"{role} SHA-256 mismatch")
        return raw

    wire = read("wire")
    raw_archive = read("archive")
    require(raw_archive.endswith(b"\n") and raw_archive.count(b"\n") == 1, "expected an archive JSONL row")
    archive = begin.pinned_json(manifest.parent / spec["archive"]["path"], spec["archive"]["sha256"])
    require(begin.u64(archive["height"], "archive height") == height + 1, "archive row is not H+1")
    wire_row = json.loads(subprocess.check_output(
        [probe.resolve(), str(cutoff), *(str(word) for word in pair)], input=wire,
    ))
    block = archive["abci_block"]
    for name in ("round", "parent_round"):
        require(begin.u64(block[name], name) == wire_row[name], f"archive {name} differs from decoded wire")
    clock = normalized_clock(wire_row)
    require(toolkit["normalizer"].clock(block["time"]) == clock, "archive clock differs from decoded wire")
    header = {"height": height + 1, "round": wire_row["round"], "time": clock}

    case = {"height": height}
    for role in ("checkpoint_rmp", "reference_h", "reference_h_plus_one"):
        case[role] = save(scratch, role, read(role))
    case["successor_header"] = save_json(scratch, "decoded-header.json", header)
    checked = save_json(scratch, "decoded-case.json", case)
    return scratch / checked["path"], checked["sha256"], header
