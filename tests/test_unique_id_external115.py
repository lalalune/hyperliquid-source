#!/usr/bin/env python3
"""Tests for the node #115 rocksdb UniqueId external conversion +
byte encode/decode reconstruction.

2,400 deterministic cases: the InternalUniqueIdToExternal
transliteration against the independently structured model, and the
Encode/DecodeUniqueIdBytes round-trip plus the length gate, plus
body-hash binds to the node #115 artifact and the caller census.

Case generators (iter_to_external_cases / iter_encode_cases /
iter_decode_cases) are also used to write the committed cases.tsv,
so the packet rows are exactly the cases the tests check.
"""
import hashlib
import json
import random
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import unique_id_external115 as m

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "re-002-node115-unique-id-external-115"

MASK64 = (1 << 64) - 1


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


def _rng():
    return random.Random(0x61B0260)


def iter_to_external_cases():
    """1,200 (w0, w1, w2, flag) cases for the transform."""
    rng = _rng()
    boundary = [
        0, 1, 2, 0xFFFFFFFF, 0x100000000, 0xFFFFFFFFFFFFFFFF,
        0x8000000000000000, 0x590EB907C873E891, 0xF1598607FB45CBD8,
        0x59973F0033362349, 0xC202797692D63D58,
    ]
    for i in range(1200):
        if i < len(boundary) * 2:
            w0 = boundary[i % len(boundary)]
            w1 = boundary[(i // len(boundary)) % len(boundary)]
            w2 = boundary[(i * 7) % len(boundary)]
        else:
            w0 = rng.randrange(1 << 64)
            w1 = rng.randrange(1 << 64)
            w2 = rng.randrange(1 << 64)
        flag = bool(rng.randrange(2)) if i >= len(boundary) * 2 else bool(i % 2)
        yield {"index": i, "w0": w0, "w1": w1, "w2": w2, "flag": flag}


def iter_encode_cases():
    """600 (w0, w1, w2, flag) cases for the encoder."""
    rng = _rng()
    for i in range(600):
        if i < 12:
            w0 = [0, 1, 0xFFFFFFFFFFFFFFFF, 0x0123456789ABCDEF][i % 4]
            w1 = [0, 0xFFFFFFFFFFFFFFFF, 1, 0xFEDCBA9876543210][i % 4]
            w2 = [0, 1, 0x8000000000000000, 0x0F0F0F0F0F0F0F0F][i % 4]
        else:
            w0 = rng.randrange(1 << 64)
            w1 = rng.randrange(1 << 64)
            w2 = rng.randrange(1 << 64)
        yield {"index": i, "w0": w0, "w1": w1, "w2": w2,
               "flag": bool(i % 2)}


def iter_decode_cases():
    """600 (data, flag) cases for the decoder: valid encodings plus
    wrong-length inputs (including cross-flag lengths)."""
    rng = _rng()
    for i in range(600):
        if i < 300:
            w0 = rng.randrange(1 << 64)
            w1 = rng.randrange(1 << 64)
            w2 = rng.randrange(1 << 64)
            flag = bool(i % 2)
            data = m.encode_unique_id_bytes(w0, w1, w2, flag)
            yield {"index": i, "data": data, "flag": flag,
                   "want_ok": True, "want_w0": w0, "want_w1": w1,
                   "want_w2": w2 if flag else None}
        else:
            flag = bool(i % 2)
            expected = 24 if flag else 16
            bad_len = rng.choice([n for n in range(0, 33)
                                  if n != expected])
            data = bytes(rng.randrange(256) for _ in range(bad_len))
            yield {"index": i, "data": data, "flag": flag,
                   "want_ok": False, "want_w0": None, "want_w1": None,
                   "want_w2": None}


def test_to_external_matches_model():
    cases = 0
    for case in iter_to_external_cases():
        got = m.to_external(case["w0"], case["w1"], case["w2"],
                            case["flag"])
        want = m.to_external_model(case["w0"], case["w1"], case["w2"],
                                   case["flag"])
        assert got == want, (case, got, want)
        cases += 1
    assert cases == 1200


def test_to_external_flag_semantics():
    # Flag clear leaves the third word untouched; flag set adds the
    # two hash halves to it. The first two words do not depend on it.
    w0, w1, w2 = 0x1122334455667788, 0x99AABBCCDDEEFF00, 0x1234567890ABCDEF
    a = m.to_external(w0, w1, w2, False)
    b = m.to_external(w0, w1, w2, True)
    assert a[0] == b[0] and a[1] == b[1]
    assert a[2] == w2
    assert b[2] == (w2 + b[0] + b[1]) & MASK64
    # The transform is a bijection on the first two words (necessary
    # condition for the census "bijective" name; not a proof).
    seen = set()
    rng = _rng()
    for _ in range(5000):
        x, y = rng.randrange(1 << 64), rng.randrange(1 << 64)
        out = m.to_external(x, y, 0, False)[:2]
        assert out not in seen
        seen.add(out)


def test_encode_decode_roundtrip():
    cases = 0
    for case in iter_encode_cases():
        data = m.encode_unique_id_bytes(case["w0"], case["w1"],
                                        case["w2"], case["flag"])
        assert len(data) == (24 if case["flag"] else 16)
        assert data == struct.pack(
            "<QQQ" if case["flag"] else "<QQ",
            case["w0"], case["w1"],
            *([case["w2"]] if case["flag"] else []))
        ok, words, msg = m.decode_unique_id_bytes(data, case["flag"])
        assert ok and msg == "", (case, ok, msg)
        if case["flag"]:
            assert words == (case["w0"], case["w1"], case["w2"])
        else:
            assert words == (case["w0"], case["w1"], None)
        cases += 1
    assert cases == 600


def test_decode_rejects_wrong_lengths():
    cases = 0
    for case in iter_decode_cases():
        ok, words, msg = m.decode_unique_id_bytes(case["data"],
                                                   case["flag"])
        assert ok == case["want_ok"], (case, ok)
        if case["want_ok"]:
            assert words == (case["want_w0"], case["want_w1"],
                             case["want_w2"])
            assert msg == ""
        else:
            assert words is None
            assert msg == m.DECODE_ERROR_MESSAGE
        cases += 1
    assert cases == 600


def test_decode_error_message_bytes():
    binary = BINARY.read_bytes()
    # .rodata file offset == VA for this section.
    assert binary[0x434324:0x434324 + 21] == b"Not a valid unique_id"


def test_bodies_match_census():
    binary = BINARY.read_bytes()
    census = json.loads((ROOT / m.CENSUS_PATH).read_text())
    records = {r["start"]: r for r in census["records"]}
    for start, end in m.FUNCTIONS[:3]:
        body = binary[start - 0x1000: end - 0x1000]
        digest = hashlib.sha256(body).hexdigest()
        assert digest == records[start]["target_body_sha256"], hex(start)
        assert digest == m.verify_binary(BINARY)[start]
    packet_hexes = {
        0x61B0260: PACKET / "unique_id_to_external115.hex",
        0x61B0300: PACKET / "unique_id_encode115.hex",
        0x61B0390: PACKET / "unique_id_decode115.hex",
        0x61C3E10: PACKET / "bijective_hash2x64_115.hex",
        0x61C3F60: PACKET / "bijective_hash2x64_adapter115.hex",
    }
    for start, path in packet_hexes.items():
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if start in records:
            assert digest == records[start]["target_body_sha256"], \
                hex(start)
        else:
            # No census record (below the 32-byte minimum): the .hex
            # must still equal the FDE body bytes in the binary.
            end = dict(m.FUNCTIONS)[start]
            assert path.read_bytes() == binary[start - 0x1000:
                                               end - 0x1000]


def test_caller_sites_in_binary():
    binary = BINARY.read_bytes()
    # (call site, target) from callers.tsv; each site must hold E8
    # with a rel32 landing exactly on the target.
    sites = [
        (0x5F58E63, 0x61B0260),
        (0x61B0525, 0x61B0260),
        (0x5F561EF, 0x61B0300),
        (0x5F58E7D, 0x61B0300),
        (0x61B0534, 0x61B0300),
        (0x5F5B7E6, 0x61B0390),
    ]
    for site, target in sites:
        off = site - 0x1000
        assert binary[off] == 0xE8, hex(site)
        rel = struct.unpack_from("<i", binary, off + 1)[0]
        assert site + 5 + rel == target, (hex(site), hex(target))
