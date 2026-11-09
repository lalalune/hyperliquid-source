#!/usr/bin/env python3
"""Tests for the node #115 rocksdb UniqueId human-string reconstruction.

2,400 deterministic cases: the `UniqueIdToHumanString` transliteration
(insert loop) against its independent model (16-char groups joined by
'-') over byte strings of length 0..48, and the
`InternalUniqueIdToHumanString` transliteration (pair-table decimal
fill) against its independent model (`str()` words) over random and
boundary u64 triples in both the 64x2 and 64x3 forms, plus body-hash
binds to the node #115 artifact, the relocation-explained census
source hashes, the caller censuses, and the .rodata ground truths.

The case generator lives in the tool module
(tools/unique_id_human_string115.py); the committed cases.tsv is
written from exactly the cases the tests check.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import unique_id_human_string115 as m

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / \
    "re-002-node115-unique-id-human-string-115"

M64 = (1 << 64) - 1


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
    "kind", "index", "id_hex", "w0_hex", "w1_hex", "w2_hex",
    "extended", "out",
]


def _row(case):
    row = {c: "" for c in TSV_COLUMNS}
    row["kind"] = case["kind"]
    row["index"] = str(case["index"])
    if case["kind"] == "human_hex":
        row["id_hex"] = case["id_hex"]
    else:
        row["w0_hex"] = case["w0_hex"]
        row["w1_hex"] = case["w1_hex"]
        row["w2_hex"] = case["w2_hex"]
        row["extended"] = str(case["extended"])
    row["out"] = case["out"]
    return row


def test_human_hex_matches_model():
    cases = 0
    for case in m.generate_cases():
        if case["kind"] != "human_hex":
            continue
        got = m.unique_id_to_human_string(bytes.fromhex(case["id_hex"]))
        want = m.unique_id_to_human_string_model(
            bytes.fromhex(case["id_hex"]))
        assert got == want, (case, got, want)
        assert got == case["out"]
        cases += 1
    assert cases == 1200


def test_human_internal_matches_model():
    cases = 0
    for case in m.generate_cases():
        if case["kind"] != "human_internal":
            continue
        words = (int(case["w0_hex"], 16), int(case["w1_hex"], 16),
                 int(case["w2_hex"], 16))
        got = m.internal_unique_id_to_human_string(
            words, bool(case["extended"]))
        want = m.internal_unique_id_to_human_string_model(
            words, bool(case["extended"]))
        assert got == want, (case, got, want)
        assert got == case["out"]
        cases += 1
    assert cases == 1200


def test_doc_example_and_boundaries():
    # The upstream header's example (rocksdb/unique_id.h, v8.1.1):
    # 24-byte id -> 16 hex + '-' + 16 hex + '-' + 16 hex.
    doc = bytes.fromhex(
        "6474df650323bdf0b48e64f3039308ca17284b32e7f7444b")
    assert m.unique_id_to_human_string(doc) == (
        "6474DF650323BDF0-B48E64F3039308CA-17284B32E7F7444B")
    assert m.unique_id_to_human_string(b"") == ""
    assert m.unique_id_to_human_string(b"\x00" * 8) == "0000000000000000"
    assert m.unique_id_to_human_string(b"\x00" * 16) == (
        "0000000000000000-0000000000000000")
    assert m.unique_id_to_human_string(b"\xff" * 16) == (
        "FFFFFFFFFFFFFFFF-FFFFFFFFFFFFFFFF")
    # Decimal digit-count boundaries (1..20 digits).
    for n, digits in ((0, 1), (9, 1), (10, 2), (99, 2), (100, 3),
                      (9999, 4), (10000, 5), (99999, 5), (100000, 6),
                      (999999999, 9), (10 ** 18, 19),
                      (10 ** 19 - 1, 19), (10 ** 19, 20), (M64, 20)):
        assert m.format_u64_decimal(n) == str(n), n
        assert m._decimal_digit_count(n) == digits, n
    assert m.internal_unique_id_to_human_string((0, 0, 0), False) == "{0,0}"
    assert m.internal_unique_id_to_human_string((0, 0, 0), True) == "{0,0,0}"
    assert m.internal_unique_id_to_human_string(
        (M64, M64, M64), True) == (
        "{18446744073709551615,18446744073709551615,"
        "18446744073709551615}")


def test_slice_to_string_modes():
    data = b"\x00\xab\xff\x10"
    assert m.slice_to_string(data, True) == "00ABFF10"
    assert m.slice_to_string_model(data, True) == "00ABFF10"
    assert m.slice_to_string(data, False) == data.decode("latin-1")
    assert m.slice_to_string(b"", True) == ""
    for v in range(16):
        assert m.to_hex(v) == "0123456789ABCDEF"[v]


def test_bodies_match_census():
    binary = BINARY.read_bytes()
    census = json.loads((ROOT / m.CENSUS_PATH).read_text())
    records = {r["start"]: r for r in census["records"]}
    for name, start, end, target in m.FUNCTIONS:
        body = binary[start - 0x1000: end - 0x1000]
        digest = hashlib.sha256(body).hexdigest()
        if target is None:
            # Only the 18-byte toHex helper has no census record.
            assert name == "toHex", name
            assert len(body) == 18, name
            assert body[:4] == b"\xf3\x0f\x1e\xfa"  # endbr64
            continue
        assert digest == target, name
        record = records.get(start)
        assert record is not None, name
        assert digest == record["target_body_sha256"], name
        assert record["end"] == end, name
    assert m.verify_binary(BINARY) is True
    packet_hexes = {
        0x61B0660: PACKET / "unique_id_to_human_string115.hex",
        0x61B0750: PACKET / "internal_unique_id_to_human_string115.hex",
        0x61C7E30: PACKET / "slice_to_string115.hex",
        0x61C7DA0: PACKET / "to_hex115.hex",
    }
    for start, path in packet_hexes.items():
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        target = dict((s, t) for _n, s, _e, t in m.FUNCTIONS)[start]
        assert target is None or digest == target, hex(start)
        if target is not None:
            assert digest == records[start]["target_body_sha256"], \
                hex(start)


def test_relocation_zeroed_source_hash():
    binary = BINARY.read_bytes()
    census = json.loads((ROOT / m.CENSUS_PATH).read_text())
    records = {r["start"]: r for r in census["records"]}
    for start, want in m.SOURCE_BODY_SHA256.items():
        record = records[start]
        body = bytearray(binary[start - 0x1000:record["end"] - 0x1000])
        offsets = m.RELOCATION_OFFSETS[start]
        if offsets is None:
            offsets = tuple(rel["offset"]
                            for rel in record["relocations"])
        for off in offsets:
            body[off:off + 4] = b"\x00\x00\x00\x00"
        assert hashlib.sha256(bytes(body)).hexdigest() == want, hex(start)
        assert want == record["source_body_sha256"], hex(start)


def test_caller_sites_in_binary():
    binary = BINARY.read_bytes()
    # (call site, target) from callers.tsv; each site must hold E8
    # with a rel32 landing exactly on the target.
    sites = [
        (0x5F58E88, 0x61B0660),
        (0x61AA029, 0x61B0660),
        (0x5F58DEC, 0x61B0750),
        (0x6120EEA, 0x61B0750),
        (0x6120F09, 0x61B0750),
        (0x61B0695, 0x61C7E30),
    ]
    for site, target in sites:
        off = site - 0x1000
        assert binary[off] == 0xE8, hex(site)
        rel = struct.unpack_from("<i", binary, off + 1)[0]
        assert site + 5 + rel == target, (hex(site), hex(target))
    # Whole-.text E8 censuses: exactly the sites above, no others.
    assert m.find_callers(BINARY, 0x61B0660) == [0x5F58E88, 0x61AA029]
    assert m.find_callers(BINARY, 0x61B0750) == [
        0x5F58DEC, 0x6120EEA, 0x6120F09]
    # All three InternalUniqueIdToHumanString callers pass extended=0.
    for site in (0x5F58DDF, 0x6120EC5, 0x6120EFD):
        off = site - 0x1000
        assert binary[off:off + 2] == b"\x31\xd2", hex(site)  # xor %edx,%edx


def test_rodata_ground_truths():
    binary = BINARY.read_bytes()
    assert binary[0x4496CF:0x4496D0] == b"-"
    assert binary[0x43B529:0x43B52A] == b","
    assert binary[0x432097:0x432098] == b"}"
    chunks = [0x451750, 0x453230, 0x456910, 0x453E00, 0x451DB0, 0x452BA0,
              0x455590, 0x456240, 0x456920, 0x4528D0, 0x456250, 0x453240,
              0x454870]
    table = bytearray(201)
    for j, chunk in enumerate(chunks):
        off = j * 16 if j < 12 else 185
        table[off:off + 16] = binary[chunk:chunk + 16]
    assert bytes(table[:200]) == m._PAIR_TABLE


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
        if row["kind"] == "human_hex":
            want = m.unique_id_to_human_string_model(
                bytes.fromhex(row["id_hex"]))
            assert want == row["out"]
        else:
            words = (int(row["w0_hex"], 16), int(row["w1_hex"], 16),
                     int(row["w2_hex"], 16))
            want = m.internal_unique_id_to_human_string_model(
                words, bool(int(row["extended"])))
            assert want == row["out"]
