#!/usr/bin/env python3
"""Tests for the node #115 rocksdb U64Ts comparator wrapper reconstruction.

2,400 deterministic cases: transliteration vs independent model for
`Compare` (800), `CompareTimestamp` (400),
`CompareWithoutTimestamp` (800) and the secondary-vtable `Compare`
thunk (400), plus body-hash binds to the node #115 artifact, the
relocation-explained census source hashes (compare functions only;
the destructors carry kind-42 relaxed relocations), the vtable
(RELATIVE) slot census, and the committed cases.tsv.

The case generator lives in the tool module
(tools/u64ts_comparator_wrapper115.py); the committed cases.tsv is
written from exactly the cases the tests check.
"""
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import u64ts_comparator_wrapper115 as m

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / \
    "re-002-node115-u64ts-comparator-wrapper-115"


def _binary_path():
    # Prefer the canonical artifact path, but only when it holds the
    # real binary: in this checkout it is a 134-byte git-lfs pointer,
    # so fall back to the materialized copy under work/.
    canonical = ROOT / "artifacts" / "node" / "115" / "hl-node"
    if canonical.exists():
        digest = hashlib.sha256(canonical.read_bytes()).hexdigest()
        if digest == m.ARTIFACT_SHA256:
            return canonical
    return ROOT / "work" / "hl-node-115.bin"


BINARY = _binary_path()

TSV_COLUMNS = [
    "kind", "index", "a_hex", "b_hex", "flag_a", "flag_b", "out",
]


def _row(case):
    row = {c: "" for c in TSV_COLUMNS}
    row["kind"] = case["kind"]
    row["index"] = str(case["index"])
    row["a_hex"] = case["a_hex"]
    row["b_hex"] = case.get("b_hex", "")
    if "flag_a" in case:
        row["flag_a"] = str(case["flag_a"])
        row["flag_b"] = str(case["flag_b"])
    row["out"] = str(case["out"])
    return row


def _expected(case):
    a = bytes.fromhex(case["a_hex"])
    b = bytes.fromhex(case.get("b_hex", ""))
    kind = case["kind"]
    if kind == "compare":
        return m.compare_model(a, b)
    if kind == "compare_timestamp":
        return m.compare_timestamp_model(a, b)
    if kind == "compare_without_timestamp":
        return m.compare_without_timestamp_model(
            a, case["flag_a"], b, case["flag_b"])
    if kind == "compare_thunk":
        return m.compare_model(a, b)
    raise ValueError("unknown kind %r" % kind)


def _got(case):
    a = bytes.fromhex(case["a_hex"])
    b = bytes.fromhex(case.get("b_hex", ""))
    kind = case["kind"]
    if kind == "compare":
        return m.compare(a, b)
    if kind == "compare_timestamp":
        return m.compare_timestamp(a, b)
    if kind == "compare_without_timestamp":
        return m.compare_without_timestamp(a, case["flag_a"], b,
                                           case["flag_b"])
    if kind == "compare_thunk":
        return m.compare(a, b)
    raise ValueError("unknown kind %r" % kind)


def test_all_cases_agree():
    cases = m.generate_cases()
    assert len(cases) == 2400
    counts = {}
    for case in cases:
        counts[case["kind"]] = counts.get(case["kind"], 0) + 1
        assert _got(case) == case["out"], case
        assert _expected(case) == case["out"], case
    assert counts == {
        "compare": 800,
        "compare_timestamp": 400,
        "compare_without_timestamp": 800,
        "compare_thunk": 400,
    }


def test_check_values_and_cross_properties():
    # Compare: larger timestamp sorts FIRST (descending).
    assert m.compare(b"abc" + struct.pack("<Q", 5),
                      b"abc" + struct.pack("<Q", 3)) == -1
    assert m.compare(b"abc" + struct.pack("<Q", 3),
                      b"abc" + struct.pack("<Q", 5)) == 1
    assert m.compare(b"abc" + struct.pack("<Q", 7),
                      b"abc" + struct.pack("<Q", 7)) == 0
    # Compare returns the raw memcmp value, not a normalised sign.
    assert m.compare(b"a\x00" + struct.pack("<Q", 9),
                      b"a\xff" + struct.pack("<Q", 9)) == -255
    assert m.compare(b"a\xff" + struct.pack("<Q", 9),
                      b"a\x00" + struct.pack("<Q", 9)) == 255
    # User-key length tiebreak still applies before timestamps.
    assert m.compare(b"abc" + struct.pack("<Q", 9),
                      b"abcd" + struct.pack("<Q", 1)) == -1
    assert m.compare(b"abcd" + struct.pack("<Q", 1),
                      b"abc" + struct.pack("<Q", 9)) == 1
    # Empty user key (timestamp only) compares by timestamp alone.
    assert m.compare(struct.pack("<Q", 2),
                      struct.pack("<Q", 1)) == -1
    # CompareTimestamp is ASCENDING (the opposite order).
    assert m.compare_timestamp(struct.pack("<Q", 5),
                               struct.pack("<Q", 3)) == 1
    assert m.compare_timestamp(struct.pack("<Q", 3),
                               struct.pack("<Q", 5)) == -1
    assert m.compare_timestamp(struct.pack("<Q", 0),
                               struct.pack("<Q", (1 << 64) - 1)) == -1
    assert m.compare_timestamp(struct.pack("<Q", (1 << 63)),
                               struct.pack("<Q", (1 << 63) - 1)) == 1
    # CompareWithoutTimestamp strips only flagged timestamps.
    assert m.compare_without_timestamp(
        b"key" + struct.pack("<Q", 1), 1,
        b"key" + struct.pack("<Q", 2), 1) == 0
    assert m.compare_without_timestamp(
        b"key" + struct.pack("<Q", 1), 0,
        b"key" + struct.pack("<Q", 2), 0) == -1
    assert m.compare_without_timestamp(
        b"key" + struct.pack("<Q", 1), 1,
        b"key" + struct.pack("<Q", 2), 0) == -1
    assert m.compare_without_timestamp(
        b"key" + struct.pack("<Q", 1), 0,
        b"key" + struct.pack("<Q", 2), 1) == 1
    # The thunk is the same behaviour as Compare.
    assert m.compare(b"abc" + struct.pack("<Q", 5),
                      b"abc" + struct.pack("<Q", 3)) == -1


def test_bodies_match_census():
    binary = BINARY.read_bytes()
    census = json.loads((ROOT / m.CENSUS_PATH).read_text())
    records = {r["start"]: r for r in census["records"]}
    for name, start, end, target in m.FUNCTIONS:
        body = binary[start - 0x1000: end - 0x1000]
        digest = hashlib.sha256(body).hexdigest()
        assert digest == target, name
        record = records.get(start)
        assert record is not None, name
        assert digest == record["target_body_sha256"], name
        assert record["end"] == end, name
    assert m.verify_binary(BINARY) is True
    packet_hexes = {
        0x61BD920: PACKET / "compare_timestamp115.hex",
        0x61BDB20: PACKET / "compare115.hex",
        0x61BDE00: PACKET / "compare_without_timestamp115.hex",
        0x61BDE60: PACKET / "compare_thunk115.hex",
        0x61BE120: PACKET / "destructor_d0115.hex",
        0x61BE240: PACKET / "destructor_d1115.hex",
        0x61BE360: PACKET / "destructor_thunk_d0115.hex",
        0x61BE6E0: PACKET / "destructor_thunk_d1115.hex",
    }
    for start, path in packet_hexes.items():
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        target = dict((s, t) for _n, s, _e, t in m.FUNCTIONS)[start]
        assert digest == target, hex(start)
        assert digest == records[start]["target_body_sha256"], hex(start)


def test_relocation_zeroed_source_hash():
    # Only the compare functions reproduce their census source hash
    # by zeroing relocation fields; the destructors carry kind-42
    # relaxed (mov -> lea) relocations, so no source hash is claimed
    # for them (RELOCATION_OFFSETS maps them to None).
    binary = BINARY.read_bytes()
    census = json.loads((ROOT / m.CENSUS_PATH).read_text())
    records = {r["start"]: r for r in census["records"]}
    for start, want in m.SOURCE_BODY_SHA256.items():
        record = records[start]
        body = bytearray(binary[start - 0x1000:record["end"] - 0x1000])
        offsets = m.RELOCATION_OFFSETS[start]
        assert offsets is not None, hex(start)
        for off in offsets:
            body[off:off + 4] = b"\x00\x00\x00\x00"
        assert hashlib.sha256(bytes(body)).hexdigest() == want, hex(start)
        assert want == record["source_body_sha256"], hex(start)
    for start in (0x61BE120, 0x61BE240, 0x61BE360, 0x61BE6E0):
        assert m.RELOCATION_OFFSETS[start] is None, hex(start)
        kinds = {rel["kind"]
                 for rel in records[start]["relocations"]}
        assert 42 in kinds, hex(start)


def test_no_direct_calls_or_lea():
    # Whole-.text E8 scan: no direct call lands on any claimed
    # function (they are reached only through vtable slots).
    for _name, start, _end, _target in m.FUNCTIONS:
        assert m.find_callers(BINARY, start) == [], hex(start)
    # Whole-.text E9 and LEA scans, each in a single pass.
    binary = BINARY.read_bytes()
    text_va, text_off, text_size = 0x1419300, 0x1418300, 0x4FD88A0
    text = binary[text_off:text_off + text_size]
    targets = {start for _n, start, _e, _t in m.FUNCTIONS}
    i = text.find(b"\xe9")
    while i >= 0:
        if i + 5 <= len(text):
            rel = struct.unpack_from("<i", text, i + 1)[0]
            assert text_va + i + 5 + rel not in targets, hex(text_va + i)
        i = text.find(b"\xe9", i + 1)
    i = text.find(bytes([0x48, 0x8D]))
    while i >= 0:
        if i + 7 <= len(text):
            modrm = text[i + 2]
            if modrm & 0xC7 == 0x05:
                disp = struct.unpack_from("<i", text, i + 3)[0]
                assert text_va + i + 7 + disp not in targets, hex(
                    text_va + i)
        i = text.find(bytes([0x48, 0x8D]), i + 1)


def test_vtable_slots_are_relative_relocations():
    text = subprocess.run(
        ["readelf", "-r", str(BINARY)], capture_output=True, text=True,
        check=True).stdout
    import re
    entries = {}
    for line in text.splitlines():
        match = re.match(r"\s*([0-9a-f]+)\s+[0-9a-f]+\s+"
                         r"R_X86_64_RELATIVE\s+([0-9a-f]+)", line)
        if match:
            entries.setdefault(int(match.group(2), 16), []).append(
                int(match.group(1), 16))
    for start, slots in m.VTABLE_SLOTS.items():
        for _vtable, vptr, offset in slots:
            slot = vptr + offset
            assert slot in entries.get(start, []), (hex(start), hex(slot))
    # The secondary vtable carries offset-to-top -32 in the file.
    binary = BINARY.read_bytes()
    off = 0x64D7370 - 0x10 - 0x2000  # LOAD3: vaddr = file offset + 0x2000
    assert struct.unpack_from("<q", binary, off)[0] == -32, hex(0x64D7370)


def test_fde_ranges_match_objdump_frames():
    out = subprocess.run(
        ["objdump", "--dwarf=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    import re
    pcs = {}
    for match in re.finditer(r"FDE cie=[0-9a-f]+ pc=([0-9a-f]+)\.\."
                            r"([0-9a-f]+)", out):
        pcs[int(match.group(1), 16)] = int(match.group(2), 16)
    for _name, start, end, _target in m.FUNCTIONS:
        assert pcs.get(start) == end, hex(start)


def test_cases_tsv_matches():
    rows = (PACKET / "cases.tsv").read_text().splitlines()
    assert rows[0].split("\t") == TSV_COLUMNS
    assert len(rows) == 2401
    generated = {c["index"]: c for c in m.generate_cases()}
    assert len(generated) == 2400
    for line in rows[1:]:
        parts = line.split("\t")
        row = dict(zip(TSV_COLUMNS, parts))
        case = generated[int(row["index"])]
        assert _row(case) == row, row
        assert _expected(case) == case["out"], row
