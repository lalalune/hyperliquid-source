"""Tests for tools/probe_lookup_115.py (node #115 RE-014 lookup).

pytest-style with a plain-python __main__ runner, because pytest is
not installed on this VM; run: python3 tests/test_probe_lookup_115.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import probe_lookup_115 as m


def check(name, cond):
    if not cond:
        raise AssertionError(name)
    print("ok:", name)


def test_hash_empty_is_seed():
    check("hash empty returns seed",
          m.hash115(b"", m.SEED) == m.SEED)


def test_hash_single_word_independent():
    # Independent transcription of the one-word path: initial
    # len*mult ^ seed, add the word, multiply, xor-shift 16.
    data = b"\x01\x02\x03\x04"
    word = 0x04030201
    eax = ((4 * m.HASH_MULT) & m.MASK32) ^ m.SEED
    eax = (eax + word) & m.MASK32
    eax = (eax * m.HASH_MULT) & m.MASK32
    eax ^= eax >> 16
    check("hash single word matches independent transcription",
          m.hash115(data, m.SEED) == eax)


def test_hash_tail_independent():
    # Independent transcription of a 6-byte input (one word + 2 tail).
    data = b"\xaa\xbb\xcc\xdd\x11\x22"
    word = 0xDDCCBBAA
    eax = ((6 * m.HASH_MULT) & m.MASK32) ^ m.SEED
    eax = (eax + word) & m.MASK32
    eax = (eax * m.HASH_MULT) & m.MASK32
    eax ^= eax >> 16
    eax = (eax + (0x22 << 8)) & m.MASK32
    edx = (eax + 0x11) & m.MASK32
    edx = (edx * m.HASH_MULT) & m.MASK32
    eax = edx ^ (edx >> 24)
    check("hash word+tail matches independent transcription",
          m.hash115(data, m.SEED) == eax)


def test_hash_sensitivity():
    base = m.hash115(b"hello world", m.SEED)
    check("hash differs by seed",
          m.hash115(b"hello world", m.SEED ^ 1) != base)
    check("hash differs by input",
          m.hash115(b"hello worle", m.SEED) != base)
    check("hash differs by length",
          m.hash115(b"hello world!", m.SEED) != base)


def test_probe_round_zero_always():
    # rounds=0 still tests round 0: a word missing the mask bits
    # must miss, a word containing them must hit.
    words = [0]
    hit = m.probe_check(words, 1, 0, 0x12345678)
    prod = (0x12345678 * m.MASK_CONST) & m.MASK64
    mask = (1 << (prod & 63)) | (1 << ((prod >> 6) & 63))
    check("round 0 tested when rounds is 0 (miss)",
          hit == ((mask & ~0 & m.MASK64) == 0))
    words = [m.MASK64]
    check("round 0 tested when rounds is 0 (hit)",
          m.probe_check(words, 1, 0, 0x12345678) is True)


def test_probe_rotation_and_corruption():
    # Two rounds: word0 passes round 0, word1 must pass the
    # ror-12 mask of round 1; corrupting word1 flips hit to miss.
    h = 0x0BADF00D
    prod = (h * m.MASK_CONST) & m.MASK64
    mask0 = (1 << (prod & 63)) | (1 << ((prod >> 6) & 63))
    prod1 = m.ror64(prod, 12)
    mask1 = (1 << (prod1 & 63)) | (1 << ((prod1 >> 6) & 63))
    base = (2 * h) >> 32
    words = [0] * 4
    words[base ^ 0] = mask0
    words[base ^ 1] = mask1
    check("two-round hit", m.probe_check(words, 2, 2, h) is True)
    words[base ^ 1] &= ~mask1
    check("corruption flips hit to miss",
          m.probe_check(words, 2, 2, h) is False)


def test_gate():
    res = m.scan(False, None, 0, 16, 0, [0], None, [], 0, 0, None,
                 None, True, 0, False, None,
                 lambda p, n, s: 0, lambda: (1, 0), 0)
    check("gate returns 0 with no events",
          res.return_value == 0 and res.events == ["early_gate"])


def test_thunk_guard():
    check("thunk guard both zero",
          m.thunk_guard(0, 0) is True)
    check("thunk guard options nonzero",
          m.thunk_guard(1, 0) is False)
    check("thunk guard host nonzero",
          m.thunk_guard(0, 1) is False)


def test_miss_literal_and_status():
    res = m.scan(True, None, 0, 16, 0, [0], None, [], 0, 0, None,
                 {"words": [0], "count": 1, "rounds": 0}, True, 6,
                 False, None, lambda p, n, s: 0x12345678,
                 lambda: (1, 0), 0)
    check("miss stores literal qword",
          res.out_sentinel == 0x00FFFFFFFFFFFFFF)
    check("miss installs status 6",
          res.status == (b"\x06\x00\x00\x00\x00\x00", None))
    check("miss increments +0x208",
          res.counters["plus_0x208"] == 1)


def test_miss_status_skip_byte2():
    # The byte-2 skip is reachable on the driver path, where the
    # driver sets the -0x81 out byte: driver returns (0, 1) with
    # r9 first byte 2, so install_status is called and skips.
    res = m.scan(True, None, 0, 16, 0, [0], None, [], 0, 0, None,
                 None, True, 2,
                 False, None, lambda p, n, s: 0x12345678,
                 lambda: (0, 1), 0)
    check("status skipped when r9 first byte is 2",
          res.status is None and "status_skip_byte2" in res.events)


def test_driver_and_epilogue():
    res = m.scan(True, {"member": 1}, 0, 16, 0, [5], ["old"],
                 ["p0", "p1", "pair"], 100, 116, 9,
                 {"words": [m.MASK64], "count": 1, "rounds": 0}, True,
                 0, False, None, lambda p, n, s: 0x12345678,
                 lambda: (7, 0), 1)
    check("driver path returns out82",
          res.return_value == 7)
    check("max updated and string replaced",
          res.out_max[0] == 9 and res.out_string[0] == "pair")
    check("epilogue releases member and destroys timer",
          "member_released" in res.events
          and "timer_destroyed" in res.events)
    check("hit increments +0x200 and epilogue +0x120",
          res.counters["plus_0x200"] == 1
          and res.counters["plus_0x120"] == 1)


def test_no_probe_table_calls_driver():
    res = m.scan(True, None, 0, 16, 0, [0], None, [], 0, 0, None,
                 None, True, 0, False, None,
                 lambda p, n, s: 0, lambda: (3, 1), 0)
    check("null probe table calls driver",
          res.return_value == 3 and "driver_called" in res.events)


def test_pair_index():
    check("pair index arithmetic",
          m.pair_index(116, 100) == 2)


def test_probe_length():
    check("probe length formula",
          m.probe_length(100, 200, 40) == 52)


def test_move_record():
    dst = [b"\x01\x02\x03\x04\x05\x06", "oldptr"]
    src = [b"\x06\x00\x00\x00\x00\x00", None]
    old = m.move_record(dst, src)
    check("move installs record and zeroes source",
          dst == [b"\x06\x00\x00\x00\x00\x00", None]
          and src == [b"\x00" * 6, None] and old == "oldptr")


TESTS = [v for k, v in sorted(globals().items())
         if k.startswith("test_")]

if __name__ == "__main__":
    for t in TESTS:
        t()
    print("ALL %d TESTS PASSED" % len(TESTS))
