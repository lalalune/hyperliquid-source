#!/usr/bin/env python3
"""Tests for the node #115 rocksdb GetSstInternalUniqueId +
DecodeSessionId reconstruction.

2,400 deterministic cases: the DecodeSessionId transliteration
against the independently structured base-36 model, the Hash2x64
wrappers against the published-formula XXH3-128 reference, and the
GetSstInternalUniqueId transliteration against its independent
model, plus body-hash binds to the node #115 artifact and the
caller census.

The case generator lives in the tool module
(tools/get_sst_internal_unique_id115.py); the committed cases.tsv
is written from exactly the cases the tests check.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import get_sst_internal_unique_id115 as m

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "re-002-node115-get-sst-internal-unique-id-115"

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
    return ROOT / "artifacts" / "node" / "115" / "hl-node"


BINARY = _binary_path()

TSV_COLUMNS = [
    "kind", "index", "db_id_hex", "session_hex", "file_number_hex",
    "data_hex", "seed_hex", "write_third_word", "lenient",
    "status_code", "status_message", "out0_hex", "out1_hex", "out2_hex",
]


def _row(case):
    row = {c: "" for c in TSV_COLUMNS}
    row["kind"] = case["kind"]
    row["index"] = str(case["index"])
    if case["kind"] == "decode_session":
        row["session_hex"] = case["session_hex"]
        row["status_code"] = str(case["status_code"])
        row["status_message"] = case["status_message"]
        row["out0_hex"] = case["out0_hex"]
        row["out1_hex"] = case["out1_hex"]
    elif case["kind"] == "hash2x64":
        row["data_hex"] = case["data_hex"]
        row["seed_hex"] = case["seed_hex"]
        row["out0_hex"] = case["out0_hex"]
        row["out1_hex"] = case["out1_hex"]
    else:
        row["db_id_hex"] = case["db_id_hex"]
        row["session_hex"] = case["session_hex"]
        row["file_number_hex"] = case["file_number_hex"]
        row["write_third_word"] = str(case["write_third_word"])
        row["lenient"] = str(case["lenient"])
        row["status_code"] = str(case["status_code"])
        row["status_message"] = case["status_message"]
        row["out0_hex"] = case["out0_hex"]
        row["out1_hex"] = case["out1_hex"]
        row["out2_hex"] = case["out2_hex"]
    return row


def test_decode_matches_model():
    cases = 0
    for case in m.generate_cases():
        if case["kind"] != "decode_session":
            continue
        data = bytes.fromhex(case["session_hex"])
        got = m.decode_session_id(data)
        want = m.decode_session_id_model(data)
        assert got == want, (data, got, want)
        assert (m.STATUS_OK if got[0] else m.STATUS_NOT_SUPPORTED) == \
            case["status_code"]
        assert got[3] == case["status_message"]
        if got[0]:
            assert ("%016x" % got[1]) == case["out0_hex"]
            assert ("%016x" % got[2]) == case["out1_hex"]
        cases += 1
    assert cases == 600


def test_decode_length_gates():
    # Length 0 / 1..12 / 13..24 / 25+ hit the four distinct paths.
    for n in (0, 1, 5, 12):
        ok, s1, s2, msg = m.decode_session_id(b"0" * n)
        assert not ok and s1 is None and s2 is None
        assert msg == ("Missing db_session_id" if n == 0
                       else "Too short db_session_id"), n
    for n in (13, 20, 24):
        ok, s1, s2, msg = m.decode_session_id(b"0" * n)
        assert ok and msg == "" and s1 == 0 and s2 == 0, n
    for n in (25, 26, 40):
        ok, s1, s2, msg = m.decode_session_id(b"0" * n)
        assert not ok and msg == "Too long db_session_id", n


def test_decode_bad_digits():
    for bad in (b"-", b"_", b" ", b".", b"!", b"\x00", b"\xff", b"+"):
        s = bytearray(b"0" * 13)
        s[6] = bad[0] if len(bad) == 1 else bad[0]
        ok, s1, s2, msg = m.decode_session_id(bytes(s))
        assert not ok and msg == "Bad digit in db_session_id", bad
    # A bad digit in the low part (last 12 chars) errors the same way.
    s = bytearray(b"0" * 24)
    s[23] = ord("-")
    ok, s1, s2, msg = m.decode_session_id(bytes(s))
    assert not ok and msg == "Bad digit in db_session_id"


def test_decode_case_insensitive():
    # 'A'..'Z' and 'a'..'z' carry the same values (sub 0x37 / 0x57).
    assert m.decode_session_id(b"ABCDEFGHIJKLM") == \
        m.decode_session_id(b"abcdefghijklm")
    assert m.decode_session_id(b"AbCdEfGhIjKlM") == \
        m.decode_session_id(b"aBcDeFgHiJkLm")
    # All-'Z' 13-char string: high = 35, low = 36**12 - 1.
    ok, s1, s2, msg = m.decode_session_id(b"Z" * 13)
    assert ok and msg == ""
    assert s1 == 35 >> 2
    assert s2 == (((35 & 3) << 62)
                  | ((36 ** 12 - 1) & ((1 << 62) - 1))) & M64


def test_decode_split_formula():
    # The (high, low) split: N = high * 36**12 + low, recovered by
    # the independent model through int(s, 36) divmod.
    for s in (b"1000000000000", b"ZZZZZZZZZZZZZ", b"1234567890abc",
              b"0000000000001", b"zzzzzzzzzzzzzzzzzzzzzzzz"):
        got = m.decode_session_id(s)
        want = m.decode_session_id_model(s)
        assert got == want, (s, got, want)
        n = int(s.decode("ascii"), 36)
        high, low = divmod(n, 36 ** 12)
        assert got[1] == high >> 2
        assert got[2] == (((high & 3) << 62)
                          | (low & ((1 << 62) - 1))) & M64


def test_decode_low_bit62_is_masked():
    # low can reach 36**12 - 1 > 2**62 - 1, so its bit 62 is dropped
    # by the & 0x3fffffffffffffff in the final block: the recovered
    # low half is low & mask62, not low. This is the binary's
    # behavior, recorded here rather than smoothed over.
    s = b"0" + b"Z" * 12  # high = 0, low = 36**12 - 1
    ok, s1, s2, msg = m.decode_session_id(s)
    assert ok and s1 == 0
    assert s2 == (36 ** 12 - 1) & ((1 << 62) - 1)
    assert s2 != 36 ** 12 - 1


def test_hash2x64_matches_model():
    cases = 0
    for case in m.generate_cases():
        if case["kind"] != "hash2x64":
            continue
        data = bytes.fromhex(case["data_hex"])
        if case["seed_hex"]:
            seed = int(case["seed_hex"], 16)
            got = m.hash2x64(data, seed=seed)
            want = m.hash2x64_model(data, seed=seed)
        else:
            got = m.hash2x64(data)
            want = m.hash2x64_model(data)
        assert got == want, (data, got, want)
        # Wrapper order: out1 = high64, out2 = low64.
        assert ("%016x" % got[0]) == case["out1_hex"]
        assert ("%016x" % got[1]) == case["out0_hex"]
        cases += 1
    assert cases == 600


def test_hash2x64_published_anchor():
    # Published XXH3_128bits(b"", 0) anchor.
    assert m.hash2x64(b"") == (0x99AA06D3014798D8, 0x6001C324468D497F)
    assert m.hash2x64(b"", seed=0) == m.hash2x64(b"")
    low, high = m.xxh3_128bits(b"")
    assert (low, high) == (0x6001C324468D497F, 0x99AA06D3014798D8)


def test_get_sst_matches_model():
    cases = 0
    for case in m.generate_cases():
        if case["kind"] != "get_sst":
            continue
        got = m.get_sst_internal_unique_id(
            bytes.fromhex(case["db_id_hex"]),
            bytes.fromhex(case["session_hex"]),
            int(case["file_number_hex"], 16),
            bool(case["write_third_word"]), bool(case["lenient"]))
        want = m.get_sst_internal_unique_id_model(
            bytes.fromhex(case["db_id_hex"]),
            bytes.fromhex(case["session_hex"]),
            int(case["file_number_hex"], 16),
            bool(case["write_third_word"]), bool(case["lenient"]))
        assert got == want, (case, got, want)
        assert got["status_code"] == case["status_code"]
        assert got["status_message"] == case["status_message"]
        cases += 1
    assert cases == 1200


def test_get_sst_strict_errors():
    db = b"0192a3f4-5b6c-7d8e-9f01-23456789abcd"
    sess = b"0123456789abcd"
    # Empty db_id -> Missing db_id (code 3), before any other check.
    r = m.get_sst_internal_unique_id(b"", sess, 7)
    assert r["status_code"] == 3 and r["status_message"] == "Missing db_id"
    assert r["out0"] is None and r["out1"] is None and r["out2"] is None
    # File number 0 -> Missing or bad file number.
    r = m.get_sst_internal_unique_id(db, sess, 0)
    assert r["status_code"] == 3
    assert r["status_message"] == "Missing or bad file number"
    # Empty session -> Missing db_session_id.
    r = m.get_sst_internal_unique_id(db, b"", 7)
    assert r["status_code"] == 3
    assert r["status_message"] == "Missing db_session_id"
    # Bad session content -> the decode error propagates, out untouched.
    r = m.get_sst_internal_unique_id(db, b"0123456789ab!", 7)
    assert r["status_code"] == 3
    assert r["status_message"] == "Bad digit in db_session_id"
    assert r["out0"] is None
    # Check order: empty db_id wins over file_number 0.
    r = m.get_sst_internal_unique_id(b"", sess, 0)
    assert r["status_message"] == "Missing db_id"


def test_get_sst_success_shape():
    db = b"0192a3f4-5b6c-7d8e-9f01-23456789abcd"
    sess = b"0123456789abcd"
    ok, s1, s2, _ = m.decode_session_id(sess)
    assert ok
    high, low = m.hash2x64(db, seed=s1)
    r = m.get_sst_internal_unique_id(db, sess, 7)
    assert r["status_code"] == 0 and r["status_message"] == ""
    assert r["out0"] == s2
    assert r["out1"] == (7 ^ high) & M64
    assert r["out2"] is None  # third word not written, flag clear
    r3 = m.get_sst_internal_unique_id(db, sess, 7, write_third_word=True)
    assert r3["out0"] == s2 and r3["out1"] == (7 ^ high) & M64
    assert r3["out2"] == low
    # The first two words do not depend on the flag.
    assert (r["out0"], r["out1"]) == (r3["out0"], r3["out1"])


def test_get_sst_lenient_fallback():
    db = b"0192a3f4-5b6c-7d8e-9f01-23456789abcd"
    # A session the decoder rejects still yields an id in lenient
    # mode, from the unseeded Hash2x64 of the raw session string.
    bad = b"0123456789ab!"
    high, low = m.hash2x64(bad)
    r = m.get_sst_internal_unique_id(db, bad, 7, lenient=True)
    assert r["status_code"] == 0 and r["status_message"] == ""
    assert r["out0"] == low
    h1, _ = m.hash2x64(db, seed=high)
    assert r["out1"] == (7 ^ h1) & M64
    # Empty session and file number 0 are also tolerated when lenient.
    r = m.get_sst_internal_unique_id(b"", b"", 0, lenient=True)
    assert r["status_code"] == 0
    # ... while the same inputs are errors in strict mode.
    r = m.get_sst_internal_unique_id(b"", b"", 0, lenient=False)
    assert r["status_code"] == 3
    assert r["status_message"] == "Missing db_id"


def test_get_sst_lenient_zero_low_fixup():
    # The binary replaces a zero low word from the fallback hash with
    # (high | 1). No random search can hit low == 0, so the branch
    # is exercised by stubbing the hash to return (high, 0).
    real = m.hash2x64
    try:
        m.hash2x64 = lambda data, seed=None: (0x1122334455667788, 0)
        r = m.get_sst_internal_unique_id(
            b"db", b"bad-session!", 9, lenient=True)
        assert r["status_code"] == 0
        assert r["out0"] == 0x1122334455667789  # (high | 1)
    finally:
        m.hash2x64 = real


def test_error_message_bytes():
    binary = BINARY.read_bytes()
    # .rodata file offset == VA for this section.
    assert binary[0x43430E:0x43430E + 21] == b"Missing db_session_id"
    assert binary[0x435387:0x435387 + 23] == b"Too short db_session_id"
    assert binary[0x44B53F:0x44B53F + 22] == b"Too long db_session_id"
    assert binary[0x43333E:0x43333E + 26] == b"Bad digit in db_session_id"
    assert binary[0x44EEC0:0x44EEC0 + 13] == b"Missing db_id"
    assert binary[0x440B78:0x440B78 + 26] == b"Missing or bad file number"
    assert binary[0x43430E:0x43430E + 21] == b"Missing db_session_id"


def test_bodies_match_census():
    binary = BINARY.read_bytes()
    census = json.loads((ROOT / m.CENSUS_PATH).read_text())
    records = {r["start"]: r for r in census["records"]}
    for name, start, end, target in m.FUNCTIONS:
        body = binary[start - 0x1000: end - 0x1000]
        digest = hashlib.sha256(body).hexdigest()
        assert digest == target, name
        assert digest == records[start]["target_body_sha256"], name
    assert m.verify_binary(BINARY) is True
    packet_hexes = {
        0x61AF500: PACKET / "decode_session_id115.hex",
        0x61AFFE0: PACKET / "get_sst_internal_unique_id115.hex",
        0x61C3DB0: PACKET / "hash2x64_unseeded115.hex",
        0x61C3DE0: PACKET / "hash2x64_seeded115.hex",
    }
    for start, path in packet_hexes.items():
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert digest == records[start]["target_body_sha256"], hex(start)


def test_caller_sites_in_binary():
    binary = BINARY.read_bytes()
    # (call site, target) from callers.tsv; each site must hold E8
    # with a rel32 landing exactly on the target.
    sites = [
        (0x5DAF6E8, 0x61AFFE0), (0x5E0D88E, 0x61AFFE0),
        (0x5E20111, 0x61AFFE0), (0x5EC2128, 0x61AFFE0),
        (0x5EE4DB1, 0x61AFFE0), (0x6120BC5, 0x61AFFE0),
        (0x61B04DE, 0x61AFFE0),
        (0x61B0062, 0x61AF500), (0x61B0133, 0x61AF500),
        (0x61B01C1, 0x61C3DB0), (0x602E9BD, 0x61C3DB0),
        (0x61B016D, 0x61C3DE0),
    ]
    for site, target in sites:
        off = site - 0x1000
        assert binary[off] == 0xE8, hex(site)
        rel = struct.unpack_from("<i", binary, off + 1)[0]
        assert site + 5 + rel == target, (hex(site), hex(target))


def test_cases_tsv_matches():
    rows = (PACKET / "cases.tsv").read_text().splitlines()
    assert rows[0].split("\t") == TSV_COLUMNS
    assert len(rows) == 2401
    for line in rows[1:]:
        parts = line.split("\t")
        row = dict(zip(TSV_COLUMNS, parts))
        kind = row["kind"]
        if kind == "decode_session":
            data = bytes.fromhex(row["session_hex"])
            ok, s1, s2, msg = m.decode_session_id_model(data)
            assert int(row["status_code"]) == \
                (m.STATUS_OK if ok else m.STATUS_NOT_SUPPORTED)
            assert row["status_message"] == msg
            if ok:
                assert row["out0_hex"] == "%016x" % s1
                assert row["out1_hex"] == "%016x" % s2
        elif kind == "hash2x64":
            data = bytes.fromhex(row["data_hex"])
            if row["seed_hex"]:
                high, low = m.hash2x64_model(
                    data, seed=int(row["seed_hex"], 16))
            else:
                high, low = m.hash2x64_model(data)
            assert row["out0_hex"] == "%016x" % low
            assert row["out1_hex"] == "%016x" % high
        else:
            want = m.get_sst_internal_unique_id_model(
                bytes.fromhex(row["db_id_hex"]),
                bytes.fromhex(row["session_hex"]),
                int(row["file_number_hex"], 16),
                bool(int(row["write_third_word"])),
                bool(int(row["lenient"])))
            assert want["status_code"] == int(row["status_code"])
            assert want["status_message"] == row["status_message"]
            if want["out0"] is not None:
                assert row["out0_hex"] == "%016x" % want["out0"]
                assert row["out1_hex"] == "%016x" % want["out1"]
            if want["out2"] is not None:
                assert row["out2_hex"] == "%016x" % want["out2"]
