"""Tests for the node #115 hash callee model (0x61c3530).

Run under plain python3 (pytest is not installed on this VM):
    python3 tests/test_hash_callee_61c3530_115.py

The golden vectors below were produced by the model and confirmed
against the original binary bytes under Unicorn emulation (see
the packet's differential.py: 1053 cases, 0 mismatches). They pin
every length arm of the window: 0, 1..3, 4..8, 9..16 and the four
accumulator bands 17..32, 33..64, 65..96, 97..128, plus the two
delegation boundaries (129..240 -> 0x61c3230, 241+ -> 0x61c2cb0).
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from hash_callee_61c3530_115 import (  # noqa: E402
    C_A, C_B, DELEGATE_LONG, DELEGATE_MID, P1, P2, P3,
    DelegatedHash, delegate_target, hash_callee)


# (payload, seed, expected) — one or more per length arm.
VECTORS = [
    (b"", 0x0000000000000000, 0x5342C3010FE1DD04),
    (b"", 0xA5155AE5E937AA16, 0xBF8CC791EFDB763A),
    (b"a", 0x0000000000000000, 0x88D868BF607681C7),
    (b"ab", 0x0000000000000001, 0x1C2930678E30C1E8),
    (b"abc", 0xD28AAD72F49BD50B, 0xBC1A05F0FC282BBB),
    (b"abcd", 0x0000000000000000, 0x97A5BA1D02E8378C),
    (b"hello", 0x77A00858DDD37F21, 0xA33D9D0C5D769A3F),
    (bytes(8), 0x0000000000000003, 0xE297AFA78D8CF389),
    (b"123456789", 0x0000000000000000, 0xAC4F8BA14FB14987),
    (bytes(range(16)), 0xFFFFFFFFFFFFFFFF, 0x1E7011D06384D761),
    (bytes(range(17)), 0x0000000000000000, 0x6DFF1AC96EEF2848),
    (bytes(range(32)), 0x0000000000000005, 0x50A6A98FC2967F88),
    (bytes(range(33)), 0x0000000000000000, 0x836364FAED762C18),
    (bytes(range(64)), 0xD28AAD72F49BD50B, 0x1E9896C8CE29351C),
    (bytes(range(65)), 0x0000000000000000, 0x761D1AECF631FF50),
    (bytes(range(96)), 0x0000000000000009, 0x9B63A7AB04759954),
    (bytes(range(97)), 0x0000000000000000, 0xA178F7429A14E134),
    (bytes(range(128)), 0xA5155AE5E937AA16, 0x8C50B84638347837),
]


def test_golden_vectors():
    for payload, seed, want in VECTORS:
        got = hash_callee(payload, seed)
        assert got == want, (len(payload), hex(seed), hex(got), hex(want))


def test_length_zero_ignores_data():
    # The length-0 arm never dereferences the data pointer; the
    # model takes no bytes into account at all on that arm.
    assert hash_callee(b"", 7) == hash_callee(bytearray(), 7)


def test_seed_is_taken_modulo_2_64():
    assert hash_callee(b"abc", 1 << 64) == hash_callee(b"abc", 0)
    assert hash_callee(b"abc", (1 << 64) + 5) == hash_callee(b"abc", 5)


def test_delegation_boundaries():
    assert delegate_target(0) is None
    assert delegate_target(128) is None
    assert delegate_target(129) == DELEGATE_MID == 0x61C3230
    assert delegate_target(240) == DELEGATE_MID
    assert delegate_target(241) == DELEGATE_LONG == 0x61C2CB0
    assert delegate_target(1 << 20) == DELEGATE_LONG
    for n, target in ((129, DELEGATE_MID), (240, DELEGATE_MID),
                      (241, DELEGATE_LONG), (1000, DELEGATE_LONG)):
        try:
            hash_callee(bytes(n), 0)
        except DelegatedHash as exc:
            assert exc.target == target and exc.length == n
        else:
            raise AssertionError("length %d did not delegate" % n)


def test_band_edges_differ():
    # Adjacent lengths across a band edge hash differently for the
    # same prefix bytes (the band structure is length-sensitive).
    base = bytes(range(256))
    for lo in (16, 32, 64, 96, 127):
        assert hash_callee(base[:lo], 0) != hash_callee(base[:lo + 1], 0)


def test_constants_match_packet_records():
    assert P1 == 0x9E3779B185EBCA87
    assert P2 == 0xC2B2AE3D27D4EB4F
    assert P3 == 0x165667B19E3779F9
    assert C_A == 0xBE4BA423396CFEB8
    assert C_B == 0x1CAD21F72C81017C


def test_packet_checks():
    here = os.path.dirname(__file__)
    packet = os.path.join(here, "..", "research", "work-items",
                          "RE-001-hash-callee-61c3530-115", "records.json")
    records = json.load(open(packet))
    assert records["window"]["start"] == "0x61c3530"
    assert records["window"]["end"] == "0x61c389d"
    assert records["window"]["artifact_sha256"] == (
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    assert len(records["census"]["direct_calls"]) == 108
    assert records["census"]["tail_jumps"] == []
    assert records["delegation"]["mid"]["target"] == "0x61c3230"
    assert records["delegation"]["long"]["target"] == "0x61c2cb0"


def _run_all():
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and callable(f)]
    for name, fn in fns:
        fn()
        print("ok", name)
    print("all %d tests passed" % len(fns))


if __name__ == "__main__":
    _run_all()
