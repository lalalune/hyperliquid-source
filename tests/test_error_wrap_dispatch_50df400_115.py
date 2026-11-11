"""Tests for the node #115 error-wrap dispatch model
(tools/error_wrap_dispatch_50df400_115.py, RE-001 work item
RE-001-error-wrap-dispatch-50df400-115). Each check counts;
the run prints "<n> checks pass" on success.

Expectations are target-grounded, read from the
whole-function excerpt in the packet: the descriptor the
routine builds for its wrap callee, the sign-bit-flip
discriminant with its default of 4, the immediate return
for discriminants 1..3, the discriminant-0 drop of the
+0x10 payload word, and the GOT-resolved tagged drop of
the +0x08 payload word everywhere else (except tag 0,
which drops nothing).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from error_wrap_dispatch_50df400_115 import (  # noqa: E402
    DESCRIPTOR_FN,
    DESCRIPTOR_ID,
    DESCRIPTOR_THUNK,
    build_descriptor,
    discriminant,
    error_wrap,
)

CHECKS = [0]

MEM_SIZE = 0x10000
OUT = 0x2000
VALUE = 0x4000
WORD_A = 0xAAAAAAAAAAAAAAAA
WORD_B = 0xBBBBBBBBBBBBBBBB
SIGN = 0x8000000000000000


def check(condition, label):
    assert condition, label
    CHECKS[0] += 1


class Env:
    """Recording callee environment: wrap answers a preset
    result; all three callees log their arguments in order."""

    def __init__(self, result):
        self.result = result
        self.events = []

    def wrap(self, desc_id, descriptor):
        self.events.append(("wrap", desc_id, descriptor))
        return self.result

    def drop_b(self, word):
        self.events.append(("drop_b", word))

    def drop_tagged(self, word, tag, zero):
        self.events.append(("drop_tagged", word, tag, zero))


def wr64(mem, addr, value):
    mem[addr:addr + 8] = (value & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def run(tag, result=0x1234, word_a=WORD_A, word_b=WORD_B):
    mem = bytearray(MEM_SIZE)
    wr64(mem, VALUE, tag)
    wr64(mem, VALUE + 0x08, word_a)
    wr64(mem, VALUE + 0x10, word_b)
    env = Env(result)
    out = error_wrap(mem, OUT, VALUE, env)
    return out, env, mem


def main():
    # -- The descriptor handed to the wrap callee. --
    check(build_descriptor(OUT, VALUE)
          == (OUT, DESCRIPTOR_THUNK, VALUE, DESCRIPTOR_FN),
          "descriptor words in order")
    check(DESCRIPTOR_ID == 0x44E417, "descriptor id constant")
    check(DESCRIPTOR_THUNK == 0x5616320, "descriptor thunk constant")
    check(DESCRIPTOR_FN == 0x5C3F000, "descriptor fn constant")

    # -- The discriminant computation (unit level). --
    check(discriminant(0) == 4, "disc(0) is the default 4")
    check(discriminant(1) == 4, "disc(1) is the default 4")
    check(discriminant(0x7FFFFFFFFFFFFFFF) == 4,
          "disc(largest positive) is the default 4")
    check(discriminant(SIGN) == 0, "disc(sign bit alone) is 0")
    check(discriminant(SIGN | 1) == 1, "disc(sign|1) is 1")
    check(discriminant(SIGN | 2) == 2, "disc(sign|2) is 2")
    check(discriminant(SIGN | 3) == 3, "disc(sign|3) is 3")
    check(discriminant(SIGN | 4) == 4, "disc(sign|4) is 4")
    check(discriminant(0xFFFFFFFFFFFFFFFF) == 0x7FFFFFFFFFFFFFFF,
          "disc(all ones) flips the sign bit only")

    # -- Discriminants 1..3: wrap result returned, no drop,
    #    payload words never read (zero words would still
    #    return cleanly). --
    for tag in (SIGN | 1, SIGN | 2, SIGN | 3):
        out, env, _mem = run(tag)
        check(out == 0x1234, "disc 1..3 returns the wrap result")
        check(env.events == [("wrap", DESCRIPTOR_ID,
                              (OUT, DESCRIPTOR_THUNK, VALUE,
                               DESCRIPTOR_FN))],
              "disc 1..3 makes no drop call")

    # -- Discriminant 0: the +0x10 payload word is dropped
    #    by value, the +0x08 word is not touched. --
    out, env, _mem = run(SIGN)
    check(out == 0x1234, "disc 0 returns the wrap result")
    check(env.events[1:] == [("drop_b", WORD_B)],
          "disc 0 drops the +0x10 word by value")

    # -- Tag 0: discriminant 4 by default, but the explicit
    #    zero test returns before any drop. --
    out, env, _mem = run(0)
    check(out == 0x1234, "tag 0 returns the wrap result")
    check(len(env.events) == 1, "tag 0 makes no drop call")

    # -- Positive nonzero tags: discriminant 4, tagged drop
    #    of the +0x08 word with (word, tag, 0). --
    for tag in (1, 2, 3, 4, 0x7FFFFFFFFFFFFFFF):
        out, env, _mem = run(tag)
        check(env.events[1:] == [("drop_tagged", WORD_A, tag, 0)],
              "positive tag drops the +0x08 word as tagged")

    # -- Negative tags with discriminant >= 4 take the same
    #    tagged drop (including sign|4, whose discriminant
    #    equals the positive default). --
    for tag in (SIGN | 4, SIGN | 5, 0xFFFFFFFFFFFFFFFF):
        out, env, _mem = run(tag)
        check(env.events[1:] == [("drop_tagged", WORD_A, tag, 0)],
              "disc >= 4 negative tag drops the +0x08 word")

    # -- The wrap result passes through verbatim, including
    #    zero and sign-bit values, on a drop path and on a
    #    plain path. --
    out, _env, _mem = run(SIGN, result=0)
    check(out == 0, "wrap result 0 passes through")
    out, _env, _mem = run(SIGN | 2, result=SIGN)
    check(out == SIGN, "wrap result with sign bit passes through")

    # -- The value itself is never written through: all 24
    #    bytes survive every path unchanged. --
    for tag in (0, 1, SIGN, SIGN | 1, SIGN | 4):
        _out, _env, mem = run(tag)
        check(bytes(mem[VALUE:VALUE + 24])
              == (tag.to_bytes(8, "little")
                  + WORD_A.to_bytes(8, "little")
                  + WORD_B.to_bytes(8, "little")),
              "value bytes unchanged")

    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    main()
