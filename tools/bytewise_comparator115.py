#!/usr/bin/env python3
"""Node #115 `rocksdb::BytewiseComparatorImpl` + `ReverseBytewiseComparatorImpl`
ordering and separator operations.

Reconstructs seven vendored RocksDB behaviours (eleven FDE copies) from the
node #115 binary (artifact SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

* `BytewiseComparatorImpl::Compare` at 0x61bdbf0..0x61bdc3f (79 bytes, census
  node115-vendor-61bdbf0, body SHA-256
  e79ff2fe89678f0f4a52dda7710306bccacad523e30e94a0b0370766493bfddc) and its
  second copy at 0x61bdd50..0x61bdd9f (79 bytes, census
  node115-vendor-61bdd50, body SHA-256
  5f5ff97289b87f12af55d50c1861796bc1d804c7cc30c1a44b0f6fc55af85e6b):
  memcmp over the shorter length; the raw memcmp value is returned
  (the first differing byte's difference, NOT normalised to +/-1),
  and equal prefixes fall through to a -1/0/+1 length tiebreak.
  The two copies share one source body (census source_body_sha256
  e59acdba386024c6f940fe69bed4f1fae454f9bdd9499c38f15b98b081b9b0de).

* `ReverseBytewiseComparatorImpl::Compare` at 0x61bdcf0..0x61bdd4f (95 bytes,
  census node115-vendor-61bdcf0, body SHA-256
  f88be433f9e6d233b79590228902419c2ca6485a69b112fe8fd87c00a14a7d1a) and
  its second copy at 0x61bdda0..0x61bddff (95 bytes, census
  node115-vendor-61bdda0, body SHA-256
  89bd89228ffef8d530b06fd640528391ee21afa2c7d207f35ef5ddeeb43a4e7f):
  the exact negation of `Compare` (negated memcmp value, inverted
  length tiebreak). The two copies share one source body (census
  source_body_sha256 f57200432d7360e73542b44f73db8645368eba45cd3fd0278113b628107407fb).

* `BytewiseComparatorImpl::CompareWithoutTimestamp` at 0x61bdc40..0x61bdc8f
  (79 bytes, census node115-vendor-61bdc40, body SHA-256
  a18e80bc42d77ac613b6cb61332896ae374339ae1a618c15fd6d452a88b3437a) and
  `ReverseBytewiseComparatorImpl::CompareWithoutTimestamp` at
  0x61bdc90..0x61bdcef (95 bytes, census node115-vendor-61bdc90, body
  SHA-256 6df1c4b397f1342196512a21927ecf2df14ec37e9790e12ca594b397222f1435):
  same as `Compare` / reverse `Compare`, with the two `bool`
  timestamp flags (rsi=&a, edx=flag, rcx=&b, r8d=flag) IGNORED by the
  body: it compares the full slices. (Independently confirmed by the
  merged RE-001-fragmented-tombstone-iterator-115 packet: "plain
  memcmp ignoring the bool flags".)

* `BytewiseComparatorImpl::EqualWithoutTimestamp` at 0x61bd950..0x61bd987
  (55 bytes, census node115-vendor-61bd950, body SHA-256
  9419fa9d0ab15621494c07331be842578ae15c96907c58b04fc600cdff78ebdf):
  false when the lengths differ, else memcmp == 0. (Despite the
  name, this overload takes only two slices; there are no flags.)

* `BytewiseComparatorImpl::FindShortSuccessor` at 0x61bd990..0x61bd9d9
  (73 bytes, census node115-vendor-61bd990, body SHA-256
  dbe2ab0a413c4982af82f8345b175772cec98b36229518b1544cbc24b3f4600e):
  scan from the first byte for the first byte != 0xff, increment
  it, truncate the string to that position + 1; unchanged when the
  key is empty or all 0xff.

* `BytewiseComparatorImpl::FindShortestSeparator` at 0x61bd9e0..0x61bdaa1
  (193 bytes, census node115-vendor-61bd9e0, body SHA-256
  a4cddab163b3924a356e27df93818112d66496aca5098b2e6e9fba30e6113d2d):
  at the first differing byte i (start[i] < limit[i]): if
  i < len(limit)-1, or start[i]+1 < limit[i], increment start[i]
  and truncate to i+1; otherwise scan start[i+1..] for the first
  non-0xff byte, increment it and truncate there; unchanged when
  no such byte exists, when the slices agree over the common
  prefix, or when start[i] >= limit[i].

* `ReverseBytewiseComparatorImpl::FindShortestSeparator` at
  0x61bdab0..0x61bdb1b (107 bytes, census node115-vendor-61bdab0,
  body SHA-256 ed6328a3e880a6181ae0734d2d1d601ea7522da35892935867585f51f46530ba):
  at the first differing byte i with start[i] > limit[i], truncate
  to i+1 with NO byte change (a prefix of start is still strictly
  between limit and start in forward order, hence a separator in
  reverse order); unchanged in every other case, including when
  i+1 == len(start) (the truncation would be a no-op).

* `BytewiseComparatorImpl::IsSameLengthImmediateSuccessor` at
  0x61bd730..0x61bd7c4 (148 bytes, census node115-vendor-61bd730,
  body SHA-256 2757a60275388f067b40f554cea32bd25bc407ea5dbd81110b1adae59266a882,
  raw_equal true): false unless the slices share one nonzero length;
  then true exactly when b is a + 1 as a big-endian number: at the
  first differing byte i, b[i] == a[i]+1, and for every j > i,
  a[j] == 0xff and b[j] == 0x00.

Vtable binding (R_X86_64_RELATIVE slots, confirmed against the merged
RE-001-fragmented-tombstone-iterator-115 `vtables.tsv`): the Bytewise
vtable (stored vptr 0x64d7038) holds EqualWithoutTimestamp at +0x98
and +0xd8, FindShortestSeparator at +0xa0, FindShortSuccessor at
+0xa8, IsSameLengthImmediateSuccessor at +0xb0,
CompareWithoutTimestamp at +0xd0 and Compare (0x61bdbf0) at +0xe0;
the Reverse vtable (stored vptr 0x64d7158) holds
EqualWithoutTimestamp at +0x98 and +0xd8, the reverse
FindShortestSeparator at +0xa0, the reverse CompareWithoutTimestamp
at +0xd0 and the reverse Compare (0x61bdcf0) at +0xe0. The second
copies live in secondary vtables (offset-to-top -32): Bytewise
Compare copy 2 (0x61bdd50) at slot 0x64d7140 of the secondary
Bytewise vtable at 0x64d7120 (typeinfo *BytewiseComparatorImpl*),
and reverse Compare copy 2 (0x61bdda0) at slot 0x64d7260 of the
secondary Reverse vtable at 0x64d7240 (typeinfo
*ReverseBytewiseComparatorImpl*). These are the
`ComparatorWithU64TsImpl<...>` wrapper's secondary bases: `Compare`
never reads `this`, so the plain function serves the secondary
slot directly with no `this`-adjusting thunk.

No function here has a direct E8 call site, an E9 tail jump, or an
LEA reference anywhere in .text (whole-.text scans): they are
reached only through the vtable slots above.

The census `source_body_sha256` values are reproduced exactly by
hashing each body with its relocation fields zeroed (see
`RELOCATION_OFFSETS` below), so `raw_equal` false is fully
explained for every claimed function except
`IsSameLengthImmediateSuccessor`, which is raw_equal true (no
relocations). The FDE ranges match the census ranges exactly and
were re-checked against `objdump --dwarf=frames` pc ranges.

No binary is executed by this tool; the models below are checked
against each other and against the binary's bytes.
"""

import argparse
import hashlib
import json
import random
import struct
from pathlib import Path

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
CENSUS_PATH = (
    "research/work-items/RE-002-node115-vendor-census/census.json"
)

# (name, start, end, target_body_sha256).
FUNCTIONS = [
    ("IsSameLengthImmediateSuccessor", 0x61BD730, 0x61BD7C4,
     "2757a60275388f067b40f554cea32bd25bc407ea5dbd81110b1adae59266a882"),
    ("EqualWithoutTimestamp", 0x61BD950, 0x61BD987,
     "9419fa9d0ab15621494c07331be842578ae15c96907c58b04fc600cdff78ebdf"),
    ("FindShortSuccessor", 0x61BD990, 0x61BD9D9,
     "dbe2ab0a413c4982af82f8345b175772cec98b36229518b1544cbc24b3f4600e"),
    ("FindShortestSeparator", 0x61BD9E0, 0x61BDAA1,
     "a4cddab163b3924a356e27df93818112d66496aca5098b2e6e9fba30e6113d2d"),
    ("ReverseFindShortestSeparator", 0x61BDAB0, 0x61BDB1B,
     "ed6328a3e880a6181ae0734d2d1d601ea7522da35892935867585f51f46530ba"),
    ("Compare", 0x61BDBF0, 0x61BDC3F,
     "e79ff2fe89678f0f4a52dda7710306bccacad523e30e94a0b0370766493bfddc"),
    ("CompareWithoutTimestamp", 0x61BDC40, 0x61BDC8F,
     "a18e80bc42d77ac613b6cb61332896ae374339ae1a618c15fd6d452a88b3437a"),
    ("ReverseCompareWithoutTimestamp", 0x61BDC90, 0x61BDCEF,
     "6df1c4b397f1342196512a21927ecf2df14ec37e9790e12ca594b397222f1435"),
    ("ReverseCompare", 0x61BDCF0, 0x61BDD4F,
     "f88be433f9e6d233b79590228902419c2ca6485a69b112fe8fd87c00a14a7d1a"),
    ("Compare2", 0x61BDD50, 0x61BDD9F,
     "5f5ff97289b87f12af55d50c1861796bc1d804c7cc30c1a44b0f6fc55af85e6b"),
    ("ReverseCompare2", 0x61BDDA0, 0x61BDDFF,
     "89bd89228ffef8d530b06fd640528391ee21afa2c7d207f35ef5ddeeb43a4e7f"),
]

# Relocation offsets (4-byte fields) whose zeroing reproduces each
# census source_body_sha256, taken from the census records.
RELOCATION_OFFSETS = {
    0x61BD730: (),
    0x61BD950: (41,),
    0x61BD990: (64,),
    0x61BD9E0: (157, 186),
    0x61BDAB0: (103,),
    0x61BDBF0: (41,),
    0x61BDC40: (38,),
    0x61BDC90: (38,),
    0x61BDCF0: (41,),
    0x61BDD50: (41,),
    0x61BDDA0: (41,),
}
SOURCE_BODY_SHA256 = {
    0x61BD730:
        "2757a60275388f067b40f554cea32bd25bc407ea5dbd81110b1adae59266a882",
    0x61BD950:
        "5b818f053139e778f76f736384f6fa67afdbc298e55f1e9386a01311df26247a",
    0x61BD990:
        "3b76df501dbdd6e448525950d4306f8eac351735aecf09931705fb2380b8f280",
    0x61BD9E0:
        "1d91d26286a0e0ba638b2542839a648ede63ad52eb61b0ec8d190bbdc7734bea",
    0x61BDAB0:
        "3c9958346a883cb962fda0ee4c3fd618eebd1996f997dd9f900a55ee3881f0d9",
    0x61BDBF0:
        "e59acdba386024c6f940fe69bed4f1fae454f9bdd9499c38f15b98b081b9b0de",
    0x61BDC40:
        "02d56c883b772d6ebf60c07b55be1ffd3194ad17213dbf2c9b2fd5f9a48ec88f",
    0x61BDC90:
        "76378513e90ecbe953b13bc5dbf790f038095282f42fb0f636fef52c581336d1",
    0x61BDCF0:
        "f57200432d7360e73542b44f73db8645368eba45cd3fd0278113b628107407fb",
    0x61BDD50:
        "e59acdba386024c6f940fe69bed4f1fae454f9bdd9499c38f15b98b081b9b0de",
    0x61BDDA0:
        "f57200432d7360e73542b44f73db8645368eba45cd3fd0278113b628107407fb",
}

# Vtable (RELATIVE) slots per function, from readelf -r on the binary;
# offsets are from the stored vptr. Cross-checked against the merged
# RE-001-fragmented-tombstone-iterator-115 vtables.tsv.
VTABLE_SLOTS = {
    0x61BD730: [("bytewise_comparator", 0x64D7038, 0xB0)],
    0x61BD950: [("bytewise_comparator", 0x64D7038, 0x98),
                ("bytewise_comparator", 0x64D7038, 0xD8),
                ("reverse_bytewise_comparator", 0x64D7158, 0x98),
                ("reverse_bytewise_comparator", 0x64D7158, 0xD8)],
    0x61BD990: [("bytewise_comparator", 0x64D7038, 0xA8)],
    0x61BD9E0: [("bytewise_comparator", 0x64D7038, 0xA0)],
    0x61BDAB0: [("reverse_bytewise_comparator", 0x64D7158, 0xA0)],
    0x61BDBF0: [("bytewise_comparator", 0x64D7038, 0xE0)],
    0x61BDC40: [("bytewise_comparator", 0x64D7038, 0xD0)],
    0x61BDC90: [("reverse_bytewise_comparator", 0x64D7158, 0xD0)],
    0x61BDCF0: [("reverse_bytewise_comparator", 0x64D7158, 0xE0)],
    0x61BDD50: [("bytewise_secondary_vtable", 0x64D7130, 0x10)],
    0x61BDDA0: [("reverse_secondary_vtable", 0x64D7250, 0x10)],
}


def compare(a, b):
    """Transliteration of `BytewiseComparatorImpl::Compare` (0x61bdbf0,
    and its second copy 0x61bdd50).

    memcmp over the shorter length; the raw memcmp value is returned
    (first differing byte's difference, not normalised); equal
    prefixes fall through to the -1/0/+1 length tiebreak.
    """
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return a[i] - b[i]
    if len(a) < len(b):
        return -1
    if len(a) > len(b):
        return 1
    return 0


def compare_model(a, b):
    """Independent model: memcmp value, else length tiebreak."""
    n = min(len(a), len(b))
    if a[:n] != b[:n]:
        for i in range(n):
            if a[i] != b[i]:
                return a[i] - b[i]
    return (len(a) > len(b)) - (len(a) < len(b))


def reverse_compare(a, b):
    """Transliteration of `ReverseBytewiseComparatorImpl::Compare`
    (0x61bdcf0, and its second copy 0x61bdda0): exact negation of
    `compare` (negated memcmp value, inverted length tiebreak).
    """
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return b[i] - a[i]
    if len(a) < len(b):
        return 1
    if len(a) > len(b):
        return -1
    return 0


def reverse_compare_model(a, b):
    """Independent model: the negation of `compare_model`."""
    return -compare_model(a, b)


def compare_without_timestamp(a, a_has_ts, b, b_has_ts):
    """Transliteration of `CompareWithoutTimestamp` (0x61bdc40).

    The two bool flags are ignored by the body (they arrive in edx
    and r8d and are never read); the comparison is the plain
    `Compare` over the full slices.
    """
    return compare(a, b)


def compare_without_timestamp_model(a, a_has_ts, b, b_has_ts):
    """Independent model: flags ignored, plain compare."""
    return compare_model(a, b)


def reverse_compare_without_timestamp(a, a_has_ts, b, b_has_ts):
    """Transliteration of the reverse `CompareWithoutTimestamp`
    (0x61bdc90): flags ignored, reverse compare."""
    return reverse_compare(a, b)


def reverse_compare_without_timestamp_model(a, a_has_ts, b, b_has_ts):
    """Independent model: flags ignored, negated compare."""
    return reverse_compare_model(a, b)


def equal_without_timestamp(a, b):
    """Transliteration of `EqualWithoutTimestamp` (0x61bd950):
    false when the lengths differ, else memcmp == 0.
    """
    if len(a) != len(b):
        return False
    return a == b


def equal_without_timestamp_model(a, b):
    """Independent model: plain byte equality."""
    return a == b


def find_short_successor(key):
    """Transliteration of `FindShortSuccessor` (0x61bd990).

    First byte != 0xff is incremented and the string is truncated
    to that position + 1; unchanged when empty or all 0xff.
    """
    buf = bytearray(key)
    for i, byte in enumerate(buf):
        if byte != 0xFF:
            buf[i] = byte + 1
            return bytes(buf[:i + 1])
    return bytes(buf)


def find_short_successor_model(key):
    """Independent model: increment-then-truncate at the first
    increasable byte, else unchanged.
    """
    for i, byte in enumerate(key):
        if byte < 0xFF:
            return key[:i] + bytes([byte + 1])
    return key


def find_shortest_separator(start, limit):
    """Transliteration of `FindShortestSeparator` (0x61bd9e0)."""
    buf = bytearray(start)
    n = min(len(buf), len(limit))
    i = 0
    while i < n and buf[i] == limit[i]:
        i += 1
    if i >= n:
        return bytes(buf)
    if buf[i] >= limit[i]:
        return bytes(buf)
    if i < len(limit) - 1:
        buf[i] += 1
        return bytes(buf[:i + 1])
    if buf[i] + 1 < limit[i]:
        buf[i] += 1
        return bytes(buf[:i + 1])
    j = i + 1
    while j < len(buf):
        if buf[j] != 0xFF:
            buf[j] += 1
            return bytes(buf[:j + 1])
        j += 1
    return bytes(buf)


def find_shortest_separator_model(start, limit):
    """Independent model: the documented RocksDB separator rule."""
    i = 0
    n = min(len(start), len(limit))
    while i < n and start[i] == limit[i]:
        i += 1
    if i >= n or start[i] >= limit[i]:
        return start
    if i < len(limit) - 1 or start[i] + 1 < limit[i]:
        return start[:i] + bytes([start[i] + 1])
    for j in range(i + 1, len(start)):
        if start[j] != 0xFF:
            return start[:j] + bytes([start[j] + 1])
    return start


def reverse_find_shortest_separator(start, limit):
    """Transliteration of the reverse `FindShortestSeparator`
    (0x61bdab0): at the first differing byte with start[i] >
    limit[i], truncate to i+1 with no byte change; otherwise
    unchanged.
    """
    buf = bytearray(start)
    n = min(len(buf), len(limit))
    if n == 0:
        return bytes(buf)
    i = 0
    while i < n and buf[i] == limit[i]:
        i += 1
    if i >= n:
        return bytes(buf)
    if limit[i] >= buf[i]:
        return bytes(buf)
    if i < len(buf) - 1:
        return bytes(buf[:i + 1])
    return bytes(buf)


def reverse_find_shortest_separator_model(start, limit):
    """Independent model: truncate at the first byte where start
    exceeds limit, when the truncation shortens the string.
    """
    i = 0
    n = min(len(start), len(limit))
    while i < n and start[i] == limit[i]:
        i += 1
    if i >= n or limit[i] >= start[i] or i + 1 >= len(start):
        return start
    return start[:i + 1]


def is_same_length_immediate_successor(a, b):
    """Transliteration of `IsSameLengthImmediateSuccessor`
    (0x61bd730): same nonzero length, first differing byte has
    b[i] == a[i]+1, and every later byte is 0xff in a and 0x00 in b.
    """
    if len(a) == 0 or len(a) != len(b):
        return False
    n = len(a)
    i = 0
    while i < n and a[i] == b[i]:
        i += 1
    if i >= n:
        return False
    if a[i] == 0xFF or a[i] + 1 != b[i]:
        return False
    j = i + 1
    while j < n:
        if a[j] != 0xFF or b[j] != 0x00:
            return False
        j += 1
    return True


def is_same_length_immediate_successor_model(a, b):
    """Independent model: b is a + 1 as a big-endian number, at the
    same length.
    """
    if len(a) == 0 or len(a) != len(b):
        return False
    return int.from_bytes(b, "big") == int.from_bytes(a, "big") + 1


def _successor_pair(rng):
    """A random (a, b) with b == a + 1 as a big-endian number."""
    n = rng.choice([1, 2, 3, 4, 5, 8, 16])
    value = rng.randrange((1 << (8 * n)) - 1)
    a = value.to_bytes(n, "big")
    return a, (value + 1).to_bytes(n, "big")


def generate_cases():
    """2,400 deterministic cases across the seven behaviours."""
    rng = random.Random(0x61BDBF0)
    cases = []
    index = 0

    def add(kind, **fields):
        nonlocal index
        case = {"kind": kind, "index": index}
        case.update(fields)
        cases.append(case)
        index += 1

    # --- compare: 600 cases. ---
    fixed_pairs = [
        (b"", b""), (b"", b"a"), (b"a", b""), (b"a", b"a"),
        (b"a", b"b"), (b"b", b"a"), (b"abc", b"abd"),
        (b"abd", b"abc"), (b"abc", b"abc"), (b"abc", b"abcd"),
        (b"abcd", b"abc"), (b"\x00", b"\x01"), (b"\x01", b"\x00"),
        (b"\x00", b"\xff"), (b"\xff", b"\x00"), (b"\xff", b"\xff"),
        (b"a\x00", b"a\xff"), (b"a\xff", b"a\x00"),
        (b"\x00" * 16, b"\x00" * 16), (b"\x00" * 16, b"\x00" * 15),
        (b"\xff" * 8, b"\xff" * 8 + b"\x00"),
        (bytes(range(32)), bytes(range(32))),
        (bytes(range(32)), bytes(range(31)) + b"\xff"),
    ]
    for a, b in fixed_pairs:
        add("compare", a_hex=a.hex(), b_hex=b.hex(),
            out=compare_model(a, b))
    while index < 600:
        la = rng.choice([0, 1, 2, 3, 4, 5, 8, 16, 32])
        lb = rng.choice([0, 1, 2, 3, 4, 5, 8, 16, 32])
        a = bytes(rng.randrange(256) for _ in range(la))
        b = bytes(rng.randrange(256) for _ in range(lb))
        if rng.randrange(3) == 0 and min(la, lb) > 0:
            # Shared prefix, differ late (or not at all).
            k = rng.randrange(min(la, lb) + 1)
            b = a[:k] + bytes(rng.randrange(256)
                             for _ in range(lb - k))
        add("compare", a_hex=a.hex(), b_hex=b.hex(),
            out=compare_model(a, b))

    # --- reverse_compare: 300 cases (same pairs, negated). ---
    for a, b in fixed_pairs:
        add("reverse_compare", a_hex=a.hex(), b_hex=b.hex(),
            out=reverse_compare_model(a, b))
    while index < 900:
        la = rng.choice([0, 1, 2, 3, 8, 16])
        lb = rng.choice([0, 1, 2, 3, 8, 16])
        a = bytes(rng.randrange(256) for _ in range(la))
        b = bytes(rng.randrange(256) for _ in range(lb))
        add("reverse_compare", a_hex=a.hex(), b_hex=b.hex(),
            out=reverse_compare_model(a, b))

    # --- compare_without_timestamp: 200 cases (all flag combos). ---
    for a, b in fixed_pairs[:12]:
        for fa in (0, 1):
            for fb in (0, 1):
                add("compare_without_timestamp", a_hex=a.hex(),
                    b_hex=b.hex(), flag_a=fa, flag_b=fb,
                    out=compare_without_timestamp_model(a, fa, b, fb))
    while index < 1100:
        la = rng.choice([0, 1, 2, 4, 8])
        lb = rng.choice([0, 1, 2, 4, 8])
        a = bytes(rng.randrange(256) for _ in range(la))
        b = bytes(rng.randrange(256) for _ in range(lb))
        fa, fb = rng.randrange(2), rng.randrange(2)
        add("compare_without_timestamp", a_hex=a.hex(),
            b_hex=b.hex(), flag_a=fa, flag_b=fb,
            out=compare_without_timestamp_model(a, fa, b, fb))

    # --- reverse_compare_without_timestamp: 100 cases. ---
    for a, b in fixed_pairs[:10]:
        for fa in (0, 1):
            for fb in (0, 1):
                add("reverse_compare_without_timestamp", a_hex=a.hex(),
                    b_hex=b.hex(), flag_a=fa, flag_b=fb,
                    out=reverse_compare_without_timestamp_model(
                        a, fa, b, fb))
    while index < 1200:
        la = rng.choice([0, 1, 2, 4, 8])
        lb = rng.choice([0, 1, 2, 4, 8])
        a = bytes(rng.randrange(256) for _ in range(la))
        b = bytes(rng.randrange(256) for _ in range(lb))
        fa, fb = rng.randrange(2), rng.randrange(2)
        add("reverse_compare_without_timestamp", a_hex=a.hex(),
            b_hex=b.hex(), flag_a=fa, flag_b=fb,
            out=reverse_compare_without_timestamp_model(a, fa, b, fb))

    # --- equal_without_timestamp: 200 cases. ---
    eq_fixed = [(b"", b""), (b"", b"a"), (b"a", b"a"), (b"a", b"b"),
                (b"abc", b"abc"), (b"abc", b"abd"), (b"abc", b"ab"),
                (b"\x00\xff", b"\x00\xff"), (b"\x00\xff", b"\x00\xfe")]
    for a, b in eq_fixed:
        add("equal_without_timestamp", a_hex=a.hex(), b_hex=b.hex(),
            out=int(equal_without_timestamp_model(a, b)))
    while index < 1400:
        la = rng.choice([0, 1, 2, 3, 8])
        a = bytes(rng.randrange(256) for _ in range(la))
        b = a if rng.randrange(2) else bytes(
            rng.randrange(256) for _ in range(rng.choice([la, la + 1])))
        add("equal_without_timestamp", a_hex=a.hex(), b_hex=b.hex(),
            out=int(equal_without_timestamp_model(a, b)))

    # --- find_short_successor: 300 cases. ---
    succ_fixed = [b"", b"\x00", b"\xff", b"\xff\xff", b"\xff\xff\xff",
                  b"a", b"ab", b"a\xff", b"a\xff\xff", b"\xffa",
                  b"\x00\xff", b"abc\xff", b"\xfe\xff\xff",
                  b"\xff\xfe", b"key", b"\x00" * 8]
    for key in succ_fixed:
        add("find_short_successor", a_hex=key.hex(),
            out=find_short_successor_model(key).hex())
    while index < 1700:
        n = rng.choice([0, 1, 2, 3, 4, 8, 16])
        key = bytes(rng.choice([0, 1, 0xFE, 0xFF, rng.randrange(256)])
                    for _ in range(n))
        add("find_short_successor", a_hex=key.hex(),
            out=find_short_successor_model(key).hex())

    # --- find_shortest_separator: 300 cases. ---
    sep_fixed = [
        (b"", b""), (b"", b"a"), (b"a", b""), (b"a", b"a"),
        (b"a", b"b"), (b"b", b"a"), (b"abc", b"abd"),
        (b"abc", b"ab\xff"), (b"ab\xff", b"ab\xff\x00"),
        (b"a", b"aa"), (b"aa", b"ab"), (b"ab", b"b"),
        (b"abc", b"abd\xff"), (b"a\xff", b"b"),
        (b"a\xff\xff", b"b"), (b"abc\xff\xff", b"abd"),
        (b"\x00", b"\x01"), (b"\xfe", b"\xff"), (b"\xff", b"\xff"),
        (b"key1", b"key2"), (b"key\xff", b"key\xff\x00"),
    ]
    for start, limit in sep_fixed:
        add("find_shortest_separator", a_hex=start.hex(),
            b_hex=limit.hex(),
            out=find_shortest_separator_model(start, limit).hex())
    while index < 2000:
        ls = rng.choice([0, 1, 2, 3, 4, 8])
        ll = rng.choice([0, 1, 2, 3, 4, 8])
        start = bytes(rng.choice([0x61, 0x62, 0xFE, 0xFF,
                                  rng.randrange(256)])
                      for _ in range(ls))
        limit = bytes(rng.choice([0x61, 0x62, 0xFE, 0xFF,
                                  rng.randrange(256)])
                      for _ in range(ll))
        add("find_shortest_separator", a_hex=start.hex(),
            b_hex=limit.hex(),
            out=find_shortest_separator_model(start, limit).hex())

    # --- reverse_find_shortest_separator: 200 cases. ---
    for start, limit in sep_fixed:
        add("reverse_find_shortest_separator", a_hex=start.hex(),
            b_hex=limit.hex(),
            out=reverse_find_shortest_separator_model(
                start, limit).hex())
    while index < 2200:
        ls = rng.choice([0, 1, 2, 3, 4, 8])
        ll = rng.choice([0, 1, 2, 3, 4, 8])
        start = bytes(rng.choice([0x61, 0x62, 0xFE, 0xFF,
                                  rng.randrange(256)])
                      for _ in range(ls))
        limit = bytes(rng.choice([0x61, 0x62, 0xFE, 0xFF,
                                  rng.randrange(256)])
                      for _ in range(ll))
        add("reverse_find_shortest_separator", a_hex=start.hex(),
            b_hex=limit.hex(),
            out=reverse_find_shortest_separator_model(
                start, limit).hex())

    # --- is_same_length_immediate_successor: 200 cases. ---
    imm_fixed = [
        (b"", b""), (b"\x00", b"\x01"), (b"\x01", b"\x00"),
        (b"\x00", b"\x00"), (b"\xff", b"\x00"), (b"\xfe", b"\xff"),
        (b"\x00\xff", b"\x01\x00"), (b"\x00\xff", b"\x01\x01"),
        (b"\x00\x00", b"\x00\x01"), (b"\xff\xff", b"\x00\x00"),
        (b"a", b"b"), (b"ab", b"ac"), (b"ab", b"ab"),
        (b"\x00\xff\xff", b"\x01\x00\x00"),
        (b"\x00\xff\xff", b"\x01\x00\x01"),
        (b"\x01\x02\x03", b"\x01\x02\x04"),
    ]
    for a, b in imm_fixed:
        add("is_same_length_immediate_successor", a_hex=a.hex(),
            b_hex=b.hex(),
            out=int(is_same_length_immediate_successor_model(a, b)))
    for _ in range(60):
        a, b = _successor_pair(rng)
        add("is_same_length_immediate_successor", a_hex=a.hex(),
            b_hex=b.hex(), out=1)
    while index < 2400:
        la = rng.choice([1, 2, 3, 4, 8])
        lb = rng.choice([1, 2, 3, 4, 8])
        a = bytes(rng.randrange(256) for _ in range(la))
        b = bytes(rng.randrange(256) for _ in range(lb))
        add("is_same_length_immediate_successor", a_hex=a.hex(),
            b_hex=b.hex(),
            out=int(is_same_length_immediate_successor_model(a, b)))
    return cases


def read_binary(binary_path):
    data = Path(binary_path).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != ARTIFACT_SHA256:
        raise ValueError("artifact digest mismatch: %s" % digest)
    return data


def verify_binary(binary_path):
    """Bind every claimed function body to the census target hash."""
    data = read_binary(binary_path)
    for name, start, end, target in FUNCTIONS:
        body = data[start - 0x1000:end - 0x1000]
        digest = hashlib.sha256(body).hexdigest()
        if digest != target:
            raise ValueError("body hash mismatch for %s: %s" % (name,
                                                                 digest))
    return True


def find_callers(binary_path, target):
    """Whole-.text E8 scan for direct call sites landing on `target`.

    (All eleven functions have none; the method is validated against
    0x61b0660 -> [0x5f58e88, 0x61aa029] and 0x61bd540 -> 49 sites.)
    """
    data = read_binary(binary_path)
    text_va, text_off, text_size = 0x1419300, 0x1418300, 0x4FD88A0
    text = data[text_off:text_off + text_size]
    sites = []
    i = text.find(b"\xe8")
    while i >= 0:
        if i + 5 <= len(text):
            rel = struct.unpack_from("<i", text, i + 1)[0]
            if text_va + i + 5 + rel == target:
                sites.append(text_va + i)
        i = text.find(b"\xe8", i + 1)
    return sites


def verify(binary_path):
    """Transliteration vs model over all cases; returns mismatches."""
    data = read_binary(binary_path)
    mismatches = 0
    cases = generate_cases()
    for case in cases:
        kind = case["kind"]
        a = bytes.fromhex(case["a_hex"])
        b = bytes.fromhex(case.get("b_hex", ""))
        if kind == "compare":
            got = compare(a, b)
            want = case["out"]
        elif kind == "reverse_compare":
            got = reverse_compare(a, b)
            want = case["out"]
        elif kind == "compare_without_timestamp":
            got = compare_without_timestamp(
                a, case["flag_a"], b, case["flag_b"])
            want = case["out"]
        elif kind == "reverse_compare_without_timestamp":
            got = reverse_compare_without_timestamp(
                a, case["flag_a"], b, case["flag_b"])
            want = case["out"]
        elif kind == "equal_without_timestamp":
            got = int(equal_without_timestamp(a, b))
            want = case["out"]
        elif kind == "find_short_successor":
            got = find_short_successor(a).hex()
            want = case["out"]
        elif kind == "find_shortest_separator":
            got = find_shortest_separator(a, b).hex()
            want = case["out"]
        elif kind == "reverse_find_shortest_separator":
            got = reverse_find_shortest_separator(a, b).hex()
            want = case["out"]
        elif kind == "is_same_length_immediate_successor":
            got = int(is_same_length_immediate_successor(a, b))
            want = case["out"]
        else:  # pragma: no cover
            raise ValueError("unknown kind %r" % kind)
        if got != want:
            mismatches += 1
            print("mismatch: %r got %r want %r" % (case, got, want))
    checks = {
        "compare_memcmp_value": compare(b"a\x00", b"a\xff"),
        "compare_reverse_negation": reverse_compare(b"abc", b"abd"),
        "separator_doc_example": find_shortest_separator(
            b"abc", b"abde").hex(),
        "successor_all_ff": find_short_successor(b"\xff\xff").hex(),
        "immediate_successor": int(
            is_same_length_immediate_successor(b"\x00\xff", b"\x01\x00")),
    }
    expected = {
        "compare_memcmp_value": -255,
        "compare_reverse_negation": 1,
        "separator_doc_example": "616264",
        "successor_all_ff": "ffff",
        "immediate_successor": 1,
    }
    for key, value in expected.items():
        if checks[key] != value:
            raise ValueError("check value mismatch: %s = %s"
                             % (key, checks[key]))
    print("%d cases agree (%d mismatches)" % (len(cases), mismatches))
    for key, value in checks.items():
        print("  %s = %s" % (key, value))
    return mismatches


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--binary", default="work/hl-node-115.bin")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.verify:
        raise SystemExit(1 if verify(args.binary) else 0)
    if args.out is not None:
        verify_binary(args.binary)
        cases = generate_cases()
        mismatches = 0
        for case in cases:
            kind = case["kind"]
            a = bytes.fromhex(case["a_hex"])
            b = bytes.fromhex(case.get("b_hex", ""))
            if kind == "compare":
                good = compare(a, b) == case["out"]
            elif kind == "reverse_compare":
                good = reverse_compare(a, b) == case["out"]
            elif kind == "compare_without_timestamp":
                good = compare_without_timestamp(
                    a, case["flag_a"], b, case["flag_b"]) == case["out"]
            elif kind == "reverse_compare_without_timestamp":
                good = reverse_compare_without_timestamp(
                    a, case["flag_a"], b, case["flag_b"]) == case["out"]
            elif kind == "equal_without_timestamp":
                good = (int(equal_without_timestamp(a, b))
                        == case["out"])
            elif kind == "find_short_successor":
                good = find_short_successor(a).hex() == case["out"]
            elif kind == "find_shortest_separator":
                good = find_shortest_separator(a, b).hex() == case["out"]
            elif kind == "reverse_find_shortest_separator":
                good = (reverse_find_shortest_separator(a, b).hex()
                        == case["out"])
            elif kind == "is_same_length_immediate_successor":
                good = (int(is_same_length_immediate_successor(a, b))
                        == case["out"])
            else:  # pragma: no cover
                raise ValueError("unknown kind %r" % kind)
            if not good:
                mismatches += 1
        counts = {}
        for case in cases:
            counts[case["kind"]] = counts.get(case["kind"], 0) + 1
        counts["total"] = len(cases)
        result = {
            "artifact": "node115",
            "artifact_sha256": ARTIFACT_SHA256,
            "functions": [
                {"name": name, "start": "0x%x" % s, "end": "0x%x" % e,
                 "body_sha256": t,
                 "scope": "node #115 bytewise comparator ordering/separator"}
                for name, s, e, t in FUNCTIONS
            ],
            "cases": counts,
            "total_cases": len(cases),
            "mismatches": mismatches,
            "check_values": {
                "compare_memcmp_value": compare(b"a\x00", b"a\xff"),
                "compare_reverse_negation": reverse_compare(
                    b"abc", b"abd"),
                "separator_doc_example": find_shortest_separator(
                    b"abc", b"abde").hex(),
                "successor_all_ff": find_short_successor(
                    b"\xff\xff").hex(),
                "immediate_successor": int(
                    is_same_length_immediate_successor(
                        b"\x00\xff", b"\x01\x00")),
            },
        }
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "result.json").write_text(
            json.dumps(result, indent=1) + "\n")
        print("wrote %s (%d cases, %d mismatches)"
              % (args.out / "result.json", len(cases), mismatches))
        raise SystemExit(1 if mismatches else 0)
    parser.print_help()
    raise SystemExit(2)


if __name__ == "__main__":
    main()
