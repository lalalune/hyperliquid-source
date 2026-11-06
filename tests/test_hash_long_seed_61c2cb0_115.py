"""Tests for the node #115 hash-long with-seed model
(tools/hash_long_seed_61c2cb0_115.py, RE-001 work item
RE-001-hash-long-seed-61c2cb0-115). Each check counts; the
run prints "<n> checks pass" on success.

Expectations are target-grounded: the accumulator vectors
below were observed from the real 1393 bytes under
emulation (counting input data[i] = i & 0xff, seed 1) at
the merge hand-off, and the packet differential re-derives
them; the secret expectations are read from the .rodata
constants the body itself loads.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from hash_long_seed_61c2cb0_115 import (  # noqa: E402
    ACC_INIT,
    DEFAULT_SECRET,
    LAST_STRIPE_SECRET_OFFSET,
    MERGE_SECRET_OFFSET,
    PRIME64_1,
    SECRET_SOURCES,
    accumulate_512,
    custom_secret,
    hash_long_seed,
    merge_accs,
    scramble_acc,
    secret_bytes,
)

CHECKS = [0]

MASK = 0xFFFFFFFFFFFFFFFF
DATA = 0x1000
MEM_SIZE = 0x10000


def check(condition, label):
    assert condition, label
    CHECKS[0] += 1


class Env:
    """Recording callee environment: delegate answers a
    preset result; merge logs its arguments and answers
    with the packet's merge contract."""

    def __init__(self, result=0):
        self.result = result
        self.events = []

    def delegate(self, data, length):
        self.events.append(("delegate", data, length))
        return self.result

    def merge(self, acc, secret, start):
        self.events.append(("merge", acc, secret, start))
        return merge_accs(acc,
                          secret[MERGE_SECRET_OFFSET:
                                 MERGE_SECRET_OFFSET + 64],
                          start)


def counting_mem(length):
    mem = bytearray(MEM_SIZE)
    for i in range(length):
        mem[DATA + i] = i & 0xFF
    return mem


# Accumulator vectors observed from the real bytes at the
# merge hand-off (counting input, seed 1).
ACC_241 = (0x2B4627DEA88E6F8D, 0xCB4BE540FF8BE59D,
           0xA1476315385E7D7C, 0xB5F41BE99BCB02B1,
           0xDBC712D0AAB97FBE, 0xD99C75DCAECF8664,
           0x3D75B5232E422A5A, 0x8CF50215BA467ADD)
ACC_241_PRE_LAST = (0x4EB51028957BD606, 0x08291D89472F559C,
                    0xA5E3B1C99ECD593B, 0xE3EC5C7E58D43E34,
                    0x10980F10396B7326, 0xB33FBC35BF995605,
                    0xE8EDB9F2D345A14C, 0x6F1341F05AD56A9E)
ACC_1024 = (0x1B6CE39E712FE8D7, 0xA2B3809CD23561D4,
            0x8E144C19C31B67B7, 0xEA1E5045999F7043,
            0x9DD29EEBF3D45B2F, 0xEB98398ECC4D57F3,
            0x03CDE40C063B0C43, 0x1E863A5C3165029C)
ACC_1025 = (0xE83FB49907E932FE, 0x86F4BEC7E6CCDE05,
            0x89986BDF85E23468, 0xE03E294C8415FB60,
            0x24A79B69F75A7657, 0x244969F8A2776532,
            0x6663622857B1B181, 0x678C8C66663C3F7B)
ACC_2048 = (0xCF4B361B34D84E87, 0xD89622BD8A32EE71,
            0xCCE81CA77C656D1B, 0x2C021F1A8E9F0939,
            0x97F06D61D72B2311, 0x93852EF15CDBB9FF,
            0xFB9DB611A739580F, 0x370E28AD0F8129CF)


def merge_event(length, seed=1):
    mem = counting_mem(length)
    env = Env()
    result = hash_long_seed(mem, DATA, length, seed, env)
    merges = [e for e in env.events if e[0] == "merge"]
    assert len(merges) == 1, "exactly one merge event"
    return merges[0], result, mem


def main():
    # -- The default secret and its wiring. --
    check(len(DEFAULT_SECRET) == 24, "default secret has 24 qwords")
    check(len(SECRET_SOURCES) == 24, "24 secret sources")
    check(all(sign == (1 if i % 2 == 0 else -1)
              for i, (_addr, sign) in enumerate(SECRET_SOURCES)),
          "even sources take +seed, odd sources -seed")
    check(DEFAULT_SECRET[0] == 0xBE4BA423396CFEB8
          and DEFAULT_SECRET[1] == 0x1CAD21F72C81017C,
          "default secret opens with the pinned qwords")
    check(len(secret_bytes(DEFAULT_SECRET)) == 192,
          "default secret serialises to 192 bytes")

    # -- custom_secret: parity wiring against the seed. --
    seed = 0x0123456789ABCDEF
    custom = custom_secret(seed)
    for i, word in enumerate(DEFAULT_SECRET):
        want = (word + seed) & MASK if i % 2 == 0 \
            else (word - seed) & MASK
        check(custom[i] == want, "custom secret qword %d" % i)
    check(custom_secret(1)[0] == (DEFAULT_SECRET[0] + 1) & MASK
          and custom_secret(1)[1] == (DEFAULT_SECRET[1] - 1) & MASK,
          "seed 1 adjusts the first pair by one")

    # -- The accumulator init is the pinned constant set. --
    check(ACC_INIT == [0xC2B2AE3D, 0x9E3779B185EBCA87,
                       0xC2B2AE3D27D4EB4F, 0x165667B19E3779F9,
                       0x85EBCA77C2B2AE63, 0x85EBCA77,
                       0x27D4EB2F165667C5, 0x9E3779B1],
          "accumulator init constants")

    # -- Accumulate: the three remaining stripes of the
    #    241-byte counting input land on the observed
    #    pre-last-stripe vector. --
    mem = counting_mem(241)
    secret = custom_secret(1)
    acc = list(ACC_INIT)
    for stripe in range(3):
        accumulate_512(acc, mem, DATA + 64 * stripe,
                       secret, 8 * stripe)
    check(tuple(acc) == ACC_241_PRE_LAST,
          "acc after 3 remaining stripes (len 241)")
    # -- The last stripe reads its secret at byte offset
    #    121, not qword-aligned, and lands on the observed
    #    final vector. --
    check(LAST_STRIPE_SECRET_OFFSET == 121
          and LAST_STRIPE_SECRET_OFFSET % 8 != 0,
          "last-stripe secret offset is the unaligned 121")
    accumulate_512(acc, mem, DATA + 241 - 64, secret,
                   LAST_STRIPE_SECRET_OFFSET)
    check(tuple(acc) == ACC_241, "acc after last stripe (len 241)")

    # -- End to end through hash_long_seed: the merge event
    #    carries the observed acc, the full custom secret
    #    and start = length * PRIME64_1. --
    event, result, _mem = merge_event(241)
    check(event[1] == ACC_241, "merge acc (len 241)")
    check(event[2] == secret_bytes(custom_secret(1)),
          "merge secret (len 241)")
    check(event[3] == (241 * PRIME64_1) & MASK,
          "merge start (len 241)")
    check(result == merge_accs(event[1], event[2][11:75], event[3]),
          "return is the merge contract of the event")

    # -- Block boundaries: len 1024 is exactly one block
    #    plus scramble (no remaining stripe, no last
    #    stripe); len 1025 adds only the last stripe;
    #    len 2048 runs the scramble twice. --
    check(merge_event(1024)[0][1] == ACC_1024, "merge acc (len 1024)")
    check(merge_event(1025)[0][1] == ACC_1025, "merge acc (len 1025)")
    check(merge_event(2048)[0][1] == ACC_2048, "merge acc (len 2048)")

    # -- Scramble unit behaviour: inverts nothing, folds
    #    the top bits down, and is seed-sensitive through
    #    the secret. --
    base = list(ACC_241_PRE_LAST)
    scrambled = list(base)
    scramble_acc(scrambled, custom_secret(1))
    check(scrambled != base, "scramble changes the accumulators")
    other = list(base)
    scramble_acc(other, custom_secret(2))
    check(other != scrambled, "scramble depends on the secret")

    # -- Seed 0 delegates with the arguments untouched and
    #    never merges. --
    env = Env(result=0xFEEDFACE)
    out = hash_long_seed(counting_mem(241), DATA, 241, 0, env)
    check(out == 0xFEEDFACE, "seed 0 returns the delegate answer")
    check(env.events == [("delegate", DATA, 241)],
          "seed 0 logs exactly one delegate event")

    # -- The input window is read, never written. --
    mem = counting_mem(500)
    before = bytes(mem)
    hash_long_seed(mem, DATA, 500, 7, Env())
    check(bytes(mem) == before, "input bytes unchanged")

    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    main()
