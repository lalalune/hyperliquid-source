"""Tests for tools/u64ts_name_factory115.py: the node #115 U64Ts
comparator wrapper Name / kClassNameInternal / factory."""

import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import u64ts_name_factory115 as m

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / \
    "re-002-node115-u64ts-name-factory-115"


def _binary_path():
    # Prefer the canonical artifact path, but only when it holds the
    # real binary: in this checkout it is a 134-byte git-lfs pointer,
    # so fall back to the materialized copy under work/.
    canonical = ROOT / "artifacts" / "node" / "115" / "hl-node"
    if canonical.exists():
        digest = hashlib.sha256(canonical.read_bytes()).hexdigest()
        if digest == m.ARTIFACT_SHA256:
            return canonical
    return ROOT / "artifacts" / "node" / "115" / "hl-node"


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
    kind = case["kind"]
    if kind == "assemble":
        a = bytes.fromhex(case["a_hex"])
        b = bytes.fromhex(case.get("b_hex", ""))
        return m.assemble_stream_model([a, b]), len(a + b)
    if kind == "factory":
        return None  # checked by the replay test below
    if kind == "name_cache":
        return m.FULL_NAME
    raise ValueError("unknown kind %r" % kind)


def test_all_cases_agree():
    cases = m.generate_cases()
    assert len(cases) == 2400
    counts = {}
    for case in cases:
        counts[case["kind"]] = counts.get(case["kind"], 0) + 1
        if case["kind"] == "assemble":
            a = bytes.fromhex(case["a_hex"])
            b = bytes.fromhex(case.get("b_hex", ""))
            assert m.assemble_stream([a, b]) == a + b, case
            assert len(a + b) == case["out"], case
        elif case["kind"] == "factory":
            assert case["out"] in (0, 1), case
        elif case["kind"] == "name_cache":
            assert bytes.fromhex(case["b_hex"]) == m.FULL_NAME, case
            assert case["out"] == 1, case
    assert counts == {
        "assemble": 800,
        "factory": 800,
        "name_cache": 800,
    }
    # The anchor case is the binary's own pair.
    assert cases[0]["kind"] == "assemble"
    assert bytes.fromhex(cases[0]["a_hex"]) == m.INNER_NAME
    assert bytes.fromhex(cases[0]["b_hex"]) == m.NAME_SUFFIX
    assert cases[0]["out"] == 32


def test_factory_state_machine():
    # Every recorded run constructs exactly once and returns the
    # same token afterwards, with the full 13-field layout intact.
    cases = m.generate_cases()
    runs = {}
    for case in cases:
        if case["kind"] == "factory":
            runs.setdefault(case["a_hex"], []).append(case)
    assert runs
    for token, run in runs.items():
        fac = m.Factory(bytes.fromhex(token))
        for i, case in enumerate(run):
            inst, constructed = fac()
            assert constructed == (i == 0), case
            assert inst == bytes.fromhex(token), case
            assert [v for _o, v in fac.layout()] == \
                [v for _o, _s, v, _n in m.FACTORY_LAYOUT]
            assert case["out"] == (0 if constructed else 1), case
    # Layout values: vptrs, timestamp size, zeroed vectors.
    layout = dict((o, v) for o, _s, v, _n in m.FACTORY_LAYOUT)
    assert layout[0x00] == 0x64D7278
    assert layout[0x20] == 0x64D7370
    assert layout[0x28] == 8
    assert layout[0x30] == 0x64D7038
    assert layout[0x50] == 0x64D7130
    for off in (0x08, 0x10, 0x18, 0x38, 0x40, 0x48, 0x58):
        assert layout[off] == 0, hex(off)


def test_name_cache_state_machine():
    cache = m.NameCache()
    assert cache.guard == 0
    assert cache.atexit_registered is False
    first = cache.name()
    assert first == b"leveldb.BytewiseComparator.u64ts"
    assert cache.guard == 1
    assert cache.atexit_registered is True
    assert cache.name() is first
    assert m.k_class_name_internal() == m.FULL_NAME
    assert m.k_class_name_internal_model() == m.FULL_NAME
    assert m.forwarder_target() == 0x61BE9D0
    assert m.forwarder_bytes() == bytes.fromhex("f30f1efae907ffffff")


def test_check_values():
    assert m.k_class_name_internal() == \
        b"leveldb.BytewiseComparator.u64ts"
    assert len(m.k_class_name_internal()) == 32
    assert m.k_class_name_internal().startswith(
        b"leveldb.BytewiseComparator")
    assert m.k_class_name_internal().endswith(b".u64ts")
    assert m.k_class_name_internal()[26] == ord(".")
    # The forwarder stub jumps to the factory.
    assert m.forwarder_bytes()[4] == 0xE9
    rel = struct.unpack_from("<i", m.forwarder_bytes(), 5)[0]
    assert 0x61BEAC0 + 9 + rel == 0x61BE9D0


def test_bodies_match_census():
    binary = BINARY.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == m.ARTIFACT_SHA256
    assert m.verify_binary(BINARY) is True
    assert m.verify_source_hashes(BINARY) is True
    assert m.verify_literals(BINARY) is True
    assert m.verify_immediates(BINARY) is True
    assert m.verify_call_sites(BINARY) is True
    assert m.verify_vtable_slots(BINARY) is True


def test_direct_call_sites():
    # Whole-.text E8 scan: the factory has exactly one direct
    # caller (0x61c0aa0); kClassNameInternal has exactly one
    # (0x61beff5, inside Name); Name has none.
    assert m.find_e8_callers(BINARY, 0x61BE9D0) == [0x61C0AA0]
    assert m.find_e8_callers(BINARY, 0x61BEBD0) == [0x61BEFF5]
    assert m.find_e8_callers(BINARY, 0x61BEF90) == []
    # Whole-.text E9 scan: the factory has exactly one tail jump,
    # the 9-byte forwarder stub; the other two have none.
    assert m.find_e9_targets(BINARY, 0x61BE9D0) == [0x61BEAC4]
    assert m.find_e9_targets(BINARY, 0x61BEBD0) == []
    assert m.find_e9_targets(BINARY, 0x61BEF90) == []
    # Whole-.text LEA scan: no LEA references the three function
    # entries (Name is reached only through its vtable slot).
    binary = BINARY.read_bytes()
    text_va, text_off, text_size = 0x1419300, 0x1418300, 0x4FD7700
    text = binary[text_off:text_off + text_size]
    targets = {0x61BE9D0, 0x61BEBD0, 0x61BEF90}
    i = text.find(bytes([0x48, 0x8D]))
    while i >= 0:
        if i + 7 <= len(text):
            modrm = text[i + 2]
            if modrm & 0xC7 == 0x05:
                disp = struct.unpack_from("<i", text, i + 3)[0]
                assert text_va + i + 7 + disp not in targets, \
                    hex(text_va + i)
        i = text.find(bytes([0x48, 0x8D]), i + 1)


def test_vtable_slots_are_relative_relocations():
    text = subprocess.run(
        ["readelf", "-r", str(BINARY)], capture_output=True, text=True,
        check=True).stdout
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
    # Name sits at +0x70, not +0x68 (the #5847 packet's value):
    # +0x68 holds 0x609d980 in both the wrapper and Bytewise
    # vtables, while +0x70 holds the wrapper's Name (0x61bef90)
    # and the Bytewise Name (0x61bd720).
    assert entries[0x61BEF90] == [0x64D72E8]
    assert entries[0x61BD720] == [0x64D70A8]
    assert 0x64D72E0 in [s for vs in entries.values() for s in vs]
    # The secondary vtable carries offset-to-top -32 in the file.
    binary = BINARY.read_bytes()
    off = 0x64D7370 - 0x10 - 0x2000  # .data.rel.ro: vaddr = file + 0x2000
    assert struct.unpack_from("<q", binary, off)[0] == -32, hex(0x64D7370)


def test_fde_ranges_match_objdump_frames():
    out = subprocess.run(
        ["objdump", "--dwarf=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    pcs = {}
    for match in re.finditer(r"FDE cie=[0-9a-f]+ pc=([0-9a-f]+)\.\."
                            r"([0-9a-f]+)", out):
        pcs[int(match.group(1), 16)] = int(match.group(2), 16)
    for _name, start, end, _target, _s, _c, _r in m.FUNCTIONS:
        assert pcs.get(start) == end, hex(start)
    for _name, start, end, _target, _cid in m.ASSOCIATED_FDES:
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
        if case["kind"] == "assemble":
            a = bytes.fromhex(case["a_hex"])
            b = bytes.fromhex(case.get("b_hex", ""))
            assert m.assemble_stream([a, b]) == a + b, row
            assert len(a + b) == case["out"], row


def test_records_match():
    records = json.loads((PACKET / "records.json").read_text())
    assert records["artifact_sha256"] == m.ARTIFACT_SHA256
    assert records["total_cases"] == 2400
    assert records["mismatches"] == 0
    by_name = {f["name"]: f for f in records["functions"]}
    for name, start, end, target, _s, _c, _r in m.FUNCTIONS:
        assert by_name[name]["body_sha256"] == target, name
        assert by_name[name]["start"] == "0x%x" % start, name
        assert by_name[name]["end"] == "0x%x" % end, name
    assert records["direct_calls"]["Factory"] == ["0x61c0aa0"]
    assert records["direct_calls"]["kClassNameInternal"] == ["0x61beff5"]
    assert records["direct_calls"]["Name"] == []
    assert records["tail_jumps"]["Factory"] == ["0x61beac4"]
    assert records["vtable_slots"]["Name"][0]["offset"] == "0x70"
