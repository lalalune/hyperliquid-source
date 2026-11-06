"""Tests for the node #115 hash merge-accumulators model
(tools/hash_merge_accs_61c27f0_115.py, RE-001 work item
RE-001-hash-merge-accs-61c27f0-115). Each check counts;
the run prints "<n> checks pass" on success.

Expectations are target-grounded: the golden vectors below
were observed from the real 152 bytes of routine
0x61c27f0 under emulation (Unicorn) on the pinned inputs,
and the packet differential re-derives them. The two
secret windows are the exact 64 bytes the body's two
callers hand it: the with-seed caller's custom secret
(seed 1) at byte offset 11, and the seedless caller's
default secret at 0x97df00 + 11, read out of the binary.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from hash_merge_accs_61c27f0_115 import (  # noqa: E402
    CALL_SITES,
    PRIME64_1,
    PRIME64_2,
    ROUTINE,
    _fold64,
    avalanche,
    merge_accs,
)

CHECKS = [0]

MASK = 0xFFFFFFFFFFFFFFFF


def check(condition, label):
    assert condition, label
    CHECKS[0] += 1


# The 64 secret bytes at custom secret (seed 1) + 11: the
# window the with-seed caller 0x61c2cb0 hands the body.
CUSTOM_WIN = bytes.fromhex(
    "2cf721ad1cdfd46de9839097db7140a4a4b7b3671fcc79e6"
    "4eccc0e578815ad07dccff7221b9084674f743248edf3590"
    "e6813a264c3d2852bb91c300cb87d065")
# The 64 secret bytes at the default secret + 11
# (0x97df0b): the window the seedless caller 0x61c2890
# hands the body, read out of the work binary.
DEFAULT_WIN = bytes.fromhex(
    "49dfea66941552668dadf82350947101322cdb44ef3db164"
    "e9851b2134bc9203560438468bce804692762a034f4fa32"
    "12df70964f0dbd2201f637865c25af147")

# Accumulator vectors observed from the real with-seed
# body at its merge hand-off (counting input data[i] =
# i & 0xff, seed 1), pinned by RE-001-hash-long-seed-
# 61c2cb0-115.
ACC_241 = (0x2B4627DEA88E6F8D, 0xCB4BE540FF8BE59D,
           0xA1476315385E7D7C, 0xB5F41BE99BCB02B1,
           0xDBC712D0AAB97FBE, 0xD99C75DCAECF8664,
           0x3D75B5232E422A5A, 0x8CF50215BA467ADD)
ACC_1024 = (0x1B6CE39E712FE8D7, 0xA2B3809CD23561D4,
            0x8E144C19C31B67B7, 0xEA1E5045999F7043,
            0x9DD29EEBF3D45B2F, 0xEB98398ECC4D57F3,
            0x03CDE40C063B0C43, 0x1E863A5C3165029C)
ACC_2048 = (0xCF4B361B34D84E87, 0xD89622BD8A32EE71,
            0xCCE81CA77C656D1B, 0x2C021F1A8E9F0939,
            0x97F06D61D72B2311, 0x93852EF15CDBB9FF,
            0xFB9DB611A739580F, 0x370E28AD0F8129CF)


def main():
    # -- Identity and census facts the model carries. --
    check(ROUTINE == 0x61C27F0, "routine address")
    check(CALL_SITES == (0x61C2C8E, 0x61C31FC),
          "exactly the two pinned call sites")
    check(PRIME64_2 == 0x165667B19E3779F9,
          "avalanche multiplier is PRIME64_2")
    check(len(CUSTOM_WIN) == 64 and len(DEFAULT_WIN) == 64,
          "both caller windows are 64 bytes")

    # -- The fold primitive. --
    check(_fold64(0, 0) == 0, "fold(0, 0)")
    check(_fold64(1, 1) == 1, "fold(1, 1)")
    check(_fold64(1 << 32, 1 << 32) == 1,
          "fold(2^32, 2^32): product 2^64 folds to 1")
    check(_fold64(3, 5) == 15, "fold(3, 5)")
    check(_fold64(0xFFFFFFFFFFFFFFFF, 2) == 0xFFFFFFFFFFFFFFFF,
          "fold(2^64-1, 2): lo (2^64-2) ^ hi (1)")

    # -- The avalanche. --
    check(avalanche(0) == 0, "avalanche(0)")
    x = 0x0123456789ABCDEF
    want = x ^ (x >> 37)
    want = (want * PRIME64_2) & MASK
    want ^= want >> 32
    check(avalanche(x) == want, "avalanche step order")
    check(avalanche(PRIME64_1) == 0x21046C70342E468A,
          "avalanche(PRIME64_1) golden")

    # -- With zero accumulators and a zero window every
    #    fold term vanishes, so the result is the
    #    avalanche of the start value alone. --
    for start in (0, 1, PRIME64_1, MASK, 0xDEADBEEF):
        check(merge_accs((0,) * 8, bytes(64), start)
              == avalanche(start),
              "zero folds leave avalanche(start %#x)" % start)

    # -- Golden vectors, observed from the real bytes. --
    check(merge_accs(ACC_241, CUSTOM_WIN, (241 * PRIME64_1) & MASK)
          == 0x819FDFFBFE6F78FC,
          "golden: acc241, custom window, start 241*P1")
    check(merge_accs(ACC_1024, CUSTOM_WIN, (1024 * PRIME64_1) & MASK)
          == 0xC1724AD705B65A62,
          "golden: acc1024, custom window, start 1024*P1")
    check(merge_accs(ACC_2048, DEFAULT_WIN, (241 * PRIME64_1) & MASK)
          == 0xEE8E978D097F895C,
          "golden: acc2048, default window, start 241*P1")
    check(merge_accs(tuple(range(8)), bytes(range(64)), 1)
          == 0x66DAB08767ED37B4,
          "golden: counting acc/secret, start 1")
    check(merge_accs((MASK,) * 8, b"\xff" * 64, MASK)
          == 0x730E44304B0E4430,
          "golden: all ones")

    # -- The body reads exactly the 64-byte window at the
    #    handed pointer: bytes past offset 63 of a longer
    #    secret buffer never change the result. --
    base = merge_accs(ACC_241, CUSTOM_WIN, 7)
    longer = CUSTOM_WIN + b"\xaa" * 128
    check(merge_accs(ACC_241, longer, 7) == base,
          "secret bytes past 63 are not read")
    check(merge_accs(ACC_241, CUSTOM_WIN + b"\xaa" * 128, 7)
          == merge_accs(ACC_241, bytes(bytearray(CUSTOM_WIN)), 7),
          "window read is the first 64 bytes only")

    # -- Every accumulator word, every secret pair region
    #    and the start value reach the result. --
    probe_acc = (0x1111111111111111, 0x2222222222222222,
                 0x3333333333333333, 0x4444444444444444,
                 0x5555555555555555, 0x6666666666666666,
                 0x7777777777777777, 0x8888888888888888)
    probe = merge_accs(probe_acc, CUSTOM_WIN, 3)
    for i in range(8):
        changed = list(probe_acc)
        changed[i] ^= 1
        check(merge_accs(tuple(changed), CUSTOM_WIN, 3) != probe,
              "acc word %d reaches the result" % i)
    for off in (0, 16, 32, 48, 63):
        changed = bytearray(CUSTOM_WIN)
        changed[off] ^= 1
        check(merge_accs(probe_acc, bytes(changed), 3) != probe,
              "secret byte %d reaches the result" % off)
    check(merge_accs(probe_acc, CUSTOM_WIN, 4) != probe,
          "start value reaches the result")

    # -- Pair symmetry inside one fold: swapping the two
    #    factors of a pair (acc word with its secret
    #    partner exchanged consistently) is not claimed;
    #    what is pinned is that the two words of a pair
    #    are read against the two halves of the same
    #    16-byte secret block: moving a secret byte from
    #    the low half to the high half changes the
    #    pairing and the result. --
    swapped = bytearray(CUSTOM_WIN)
    swapped[0:8], swapped[8:16] = CUSTOM_WIN[8:16], CUSTOM_WIN[0:8]
    check(merge_accs(probe_acc, bytes(swapped), 3) != probe,
          "secret halves pair with their own acc word")

    # -- Input validation mirrors the fixed read widths. --
    for bad_acc, bad_secret in (((0,) * 7, CUSTOM_WIN),
                                ((0,) * 8, bytes(63))):
        try:
            merge_accs(bad_acc, bad_secret, 0)
        except ValueError:
            check(True, "width validation")
        else:
            check(False, "width validation")

    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    main()
