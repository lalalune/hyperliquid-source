"""Tests for the node #115 guarded mem-mapping release
model (tools/mem_mapping_destructor_d4f70_115.py, RE-001
work item RE-001-mem-mapping-destructor-d4f70-115).
Each check counts; the run prints "<n> checks pass"
and "ALL TESTS PASSED" on success.

Expectations are target-grounded, read from the
whole-function excerpt in the packet: the null guard
on the pair's pointer word (return at once, the
length word unread, no call, result 0), the single
munmap tail call with the pair's two words on the
non-null path (including a zero length), the munmap
return value passed through, and no memory written
on either path -- the pair itself is left byte-for-
byte intact.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from mem_mapping_destructor_d4f70_115 import (  # noqa: E402
    mem_mapping_release,
)

CHECKS = [0]

MEM_SIZE = 0x10000
PAIR = 0x4000


def check(condition, label):
    assert condition, label
    CHECKS[0] += 1


class Env:
    """Recording munmap stub answering a preset result."""

    def __init__(self, result):
        self.result = result
        self.events = []

    def munmap(self, ptr, length):
        self.events.append(("munmap", ptr, length))
        return self.result


def fresh_mem(ptr, length, fill=0xA5):
    mem = bytearray([fill]) * MEM_SIZE
    mem[PAIR:PAIR + 8] = (ptr & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
    mem[PAIR + 8:PAIR + 16] = \
        (length & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
    return mem


def run(ptr, length, result=0):
    mem = fresh_mem(ptr, length)
    before = bytes(mem)
    env = Env(result)
    ret = mem_mapping_release(mem, PAIR, env)
    return ret, env, bytes(mem) == before


def main():
    # Null pointer: no call, result 0, memory untouched,
    # whatever the length word holds.
    for length in (0, 1, 0x1000, 0xFFFFFFFFFFFFFFFF):
        ret, env, clean = run(0, length)
        check(env.events == [], "null ptr: no munmap call")
        check(ret == 0, "null ptr: result is 0")
        check(clean, "null ptr: memory untouched")

    # Non-null pointer: exactly one munmap with the
    # pair's two words, result passed through, memory
    # untouched (the pair is NOT zeroed by the routine).
    for ptr, length in (
        (0x7F0000001000, 0),
        (0x7F0000001000, 1),
        (0x7F0000001000, 0x1000),
        (0x1000, 0x8000000000000000),
        (0xDEADBEEF0000, 0xFFFFFFFFFFFFFFFF),
        (PAIR, 0x2000),
    ):
        for result in (0, 0xFFFFFFFFFFFFFFFF, 0x1234):
            ret, env, clean = run(ptr, length, result)
            check(env.events == [("munmap", ptr, length)],
                  "one munmap with the pair's words")
            check(ret == result, "munmap result passed through")
            check(clean, "non-null: memory untouched")

    # The pair may sit anywhere; only its first 16
    # bytes are read.
    mem = bytearray([0x5A]) * MEM_SIZE
    alt = 0x8000
    mem[alt:alt + 8] = (0x7F0000002000).to_bytes(8, "little")
    mem[alt + 8:alt + 16] = (0x3000).to_bytes(8, "little")
    env = Env(0)
    ret = mem_mapping_release(mem, alt, env)
    check(env.events == [("munmap", 0x7F0000002000, 0x3000)],
          "pair at an arbitrary address")
    check(ret == 0, "arbitrary address: result 0")

    print("%d checks pass" % CHECKS[0])
    print("ALL TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
