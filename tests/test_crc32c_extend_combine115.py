#!/usr/bin/env python3
"""Tests for the node #115 rocksdb::crc32c slow-path reconstruction.

2,400 deterministic cases: the Extend transliteration against an
independent bit-by-bit reference, and the Crc32cCombine transliteration
against the independent GF(2) advance model, plus table/body-hash binds
to the node #115 artifact and the published CRC-32C check value.
"""
import hashlib
import json
import random
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import crc32c_extend_combine115 as m

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = ROOT / "research" / "work-items" / "re-002-node115-crc32c-extend-combine-115"

MASK32 = 0xFFFFFFFF


def _rng():
    return random.Random(0x61C21D0)


def test_extend_matches_bitref():
    rng = _rng()
    lengths = [0, 1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65,
               127, 128, 129, 255, 256, 257, 511, 512, 600]
    cases = 0
    for i in range(1200):
        if i < len(lengths):
            n = lengths[i]
        else:
            n = rng.randrange(0, 601)
        data = bytes(rng.randrange(256) for _ in range(n))
        crc = rng.randrange(1 << 32)
        addr = rng.choice([0x1000, 0x1001, 0x1007, 0x100F, 0x1010])
        got = m.extend(crc, data, data_addr=addr)
        want = m.extend_bitref(crc, data)
        assert got == want, (i, n, hex(addr), hex(got), hex(want))
        cases += 1
    assert cases == 1200


def test_combine_matches_independent_model():
    rng = _rng()
    lengths = [0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64,
               100, 255, 256, 1000]
    cases = 0
    for i in range(1200):
        if i < len(lengths):
            n = lengths[i]
        else:
            n = rng.randrange(0, 1001)
        crc1 = rng.randrange(1 << 32)
        crc2 = rng.randrange(1 << 32)
        got = m.combine_translit(crc1, crc2, n)
        want = m.combine(crc1, crc2, n)
        assert got == want, (i, n, hex(got), hex(want))
        cases += 1
    assert cases == 1200


def test_combine_concatenation_identity():
    rng = _rng()
    for i in range(200):
        a = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 50)))
        b = bytes(rng.randrange(256)
                  for _ in range(rng.choice([1, 2, 3, 4, 5, 17, 100])))
        c1 = m.extend(0, a)
        c2 = m.extend(0, b)
        assert m.combine(c1, c2, len(b)) == m.extend(0, a + b), i


def test_combine_degenerate_len2_zero():
    # No early return in the binary: combine(crc1, crc2, 0) == crc1 ^ crc2.
    assert m.combine_translit(0x12345678, 0x9ABCDEF0, 0) == 0x88888888
    assert m.combine(0x12345678, 0x9ABCDEF0, 0) == 0x88888888


def test_known_vectors():
    assert m.extend(0, b"") == 0x00000000
    assert m.extend(0, b"123456789") == 0xE3069283
    assert m.extend_bitref(0, b"123456789") == 0xE3069283
    # Chained extends equal one extend over the concatenation.
    assert m.extend(m.extend(0, b"12345"), b"6789") == 0xE3069283


def test_fast_advance_matches_step_advance():
    rng = _rng()
    for _ in range(50):
        crc = rng.randrange(1 << 32)
        n = rng.randrange(0, 1001)
        assert m.advance_raw_fast(crc, n) == m.advance_raw(crc, n)


def test_combine_inner_matches_advance():
    rng = _rng()
    for p in range(32):
        for _ in range(20):
            crc = rng.randrange(1 << 32)
            acc, advanced = m._combine_inner(crc, m.COMBINE_TABLE[p])
            assert acc == m.advance_raw_fast(crc, 32 * (1 << p)), p
            assert advanced == m.advance_raw(crc, 32), p


def test_tables_match_binary():
    binary = BINARY.read_bytes()
    t0 = list(struct.unpack_from("<256I", binary, 0x97DAE0))
    assert t0 == m.base_table()
    tables = m.slice_tables()
    for base, table in ((0x97DAE0, tables[0]), (0x97D6E0, tables[1]),
                        (0x97D2E0, tables[2]), (0x97CEE0, tables[3])):
        assert list(struct.unpack_from("<256I", binary, base)) == table
    assert list(struct.unpack_from("<32I", binary, 0x97CDE0)) == list(
        m.COMBINE_TABLE)
    assert m.COMBINE_TABLE[0] == m.POLY


def test_bodies_match_census():
    binary = BINARY.read_bytes()
    census = json.loads((ROOT / m.CENSUS_PATH).read_text())
    records = {r["start"]: r for r in census["records"]}
    for start, end in ((0x61C21D0, 0x61C23B9), (0x61C2600, 0x61C26C9)):
        body = binary[start - 0x1000: end - 0x1000]
        digest = hashlib.sha256(body).hexdigest()
        assert digest == records[start]["target_body_sha256"], hex(start)
        assert digest == m.verify_binary(BINARY)[start]
    packet_hexes = {
        0x61C21D0: PACKET / "crc32c_extend_impl_slow115.hex",
        0x61C2600: PACKET / "crc32c_combine115.hex",
    }
    for start, path in packet_hexes.items():
        assert hashlib.sha256(path.read_bytes()).hexdigest() == \
            records[start]["target_body_sha256"]
