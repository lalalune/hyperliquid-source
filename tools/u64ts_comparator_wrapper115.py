#!/usr/bin/env python3
"""Node #115 `rocksdb::ComparatorWithU64TsImpl<BytewiseComparatorImpl>`
wrapper layer.

Reconstructs the wrapper the merged RE-002 bytewise-comparator packet
(#5844) left as a follow-up: the `ComparatorWithU64TsImpl` layer that
sits on top of `BytewiseComparatorImpl::Compare` /
`CompareWithoutTimestamp` and adds the 8-byte U64 timestamp suffix
handling, from the node #115 binary (artifact SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

* `ComparatorWithU64TsImpl::CompareTimestamp` at 0x61bd920..0x61bd946
  (38 bytes, census node115-vendor-61bd920, body SHA-256
  f73501ca409cc995031497f7083712bd48ae14c440d6d180596eb72d88872ef8,
  raw_equal true): the two slices ARE the timestamps; each is read as
  a little-endian u64 from the first 8 bytes of the slice data and
  compared ASCENDING (-1/0/+1). No length is consulted.

* `ComparatorWithU64TsImpl::Compare` at 0x61bdb20..0x61bdb97 (119
  bytes, census node115-vendor-61bdb20, body SHA-256
  2b7cc1dad8c2805c4e7ff60d1487072f62e07897f945006482510bb5c90780aa)
  and its secondary-vtable copy ("thunk") at 0x61bde60..0x61bded7
  (119 bytes, census node115-vendor-61bde60, body SHA-256
  94ada2c8cdf065aedc1470ab520a400baed474f0877ccdf31600f944206edc25):
  the timestamp size (8) is read from the object field at +0x28
  (primary) / +0x08 (thunk, i.e. the same field relative to the
  secondary base at +0x20); the user keys are the slices minus the
  trailing 8 bytes. The user keys are compared with the raw memcmp
  value (first differing byte's difference, NOT normalised) and the
  -1/0/+1 length tiebreak, exactly as the inner
  `BytewiseComparatorImpl::Compare` does -- but the wrapper INLINES
  the memcmp here instead of calling the inner Compare. When the
  user keys agree byte-for-byte and in length, the trailing 8-byte
  timestamps (little-endian u64) decide, in DESCENDING order: the
  LARGER timestamp sorts FIRST (a_ts < b_ts returns +1, a_ts > b_ts
  returns -1, equal returns 0). The thunk is the same body with the
  `this` offset adjusted (it reads the timestamp size at +0x08 and
  never touches `this` otherwise), mirroring the second-copy pattern
  of the inner Compare in #5844.

* `ComparatorWithU64TsImpl::CompareWithoutTimestamp` at
  0x61bde00..0x61bde5f (95 bytes, census node115-vendor-61bde00, body
  SHA-256 0dd18014e1551d62de2f292d86abc7e0c4dc2dba10509d29bde2bce106591968):
  strips the trailing 8 bytes from each slice ONLY when the
  matching bool flag is set (a_has_ts in edx, b_has_ts in r8d),
  then a plain bytewise compare (raw memcmp value, -1/0/+1 length
  tiebreak). The timestamps are never compared here. Precondition:
  a slice whose flag is set must be at least 8 bytes long (the
  body subtracts without a check; a shorter slice would underflow
  the unsigned length).

* `ComparatorWithU64TsImpl::~ComparatorWithU64TsImpl()` (D1, the
  complete-object destructor) at 0x61be240..0x61be35b (283 bytes,
  census node115-vendor-61be240, body SHA-256
  2b3332200b6ef7b55dcd9c8432913457bd8e98e1369cd72c36d54a35c3b8c6b0)
  and the deleting destructor (D0) at 0x61be120..0x61be23b (283
  bytes, census node115-vendor-61be120, body SHA-256
  33ef3e926c919da7f2896f2997f5a4ee5ed2a3ebf1f41ec5c2ee75defe7f7bd3),
  plus the secondary-base thunks D0 at 0x61be360..0x61be473 (275
  bytes, census node115-vendor-61be360, body SHA-256
  a9c2f82e7400d9e828eef348011572c5337eff5637ea38c6197f25337bab6d48)
  and D1 at 0x61be6e0..0x61be7fb (283 bytes, census
  node115-vendor-61be6e0, body SHA-256
  c7c2a86c4add966e0d13a531dde5259532535a51039c0c5d39e6aae3023144ee):
  the three vptrs are reset (primary to the wrapper vtable
  0x64d7278, secondary at +0x20 to 0x64d7370, third at +0x30 to the
  `rocksdb::Configurable` vtable 0x64d3430), then the two member
  vectors are destroyed element-wise -- each element is 48 bytes
  holding a std::string at offset 0 (libstdc++ `_M_dispose`:
  heap buffer freed with sized `operator delete(ptr, capacity+1)`
  unless the string is in SSO form) -- and each vector's storage
  buffer is freed with sized `operator delete(begin, cap_end -
  begin)`; the primary vptr is reset once more to the
  `Configurable` vtable 0x64d3430 before the second vector (at
  +0x08/+0x10/+0x18) is destroyed. D0 then frees the 96-byte object
  itself (`operator delete(this, 0x60)`); D1 returns. The thunks
  adjust `this` by -0x20 first and end the same way (thunk D0 frees
  the object with the adjusted pointer). The factory
  `BytewiseComparatorWithU64Ts` (0x61be9d0, not reconstructed here)
  confirms the layout independently: it stores ts_sz 8 at +0x28,
  the wrapper vtable at +0x00, the secondary vtable at +0x20, the
  Bytewise vtable at +0x30, the Bytewise secondary vtable at +0x50,
  and zeroes both vectors and +0x58.

Vtable binding (R_X86_64_RELATIVE slots, from `readelf -r`): the
wrapper's primary vtable (stored vptr 0x64d7278) holds D1 at +0x00,
D0 at +0x08, `Name` at +0x68, `CompareTimestamp` at +0xc8 (slot 25),
`CompareWithoutTimestamp` at +0xd0 (slot 26) and `Compare` at +0xe0
(slot 28); the secondary vtable (stored vptr 0x64d7370,
offset-to-top -32) holds thunk D1 at +0x00, thunk D0 at +0x08 and
thunk `Compare` at +0x10 (slot 2). The `Name` function (0x61bef90),
`kClassNameInternal` (0x61bebd0) and the factory (0x61be9d0) are NOT
reconstructed here (string building / construction, a follow-up).

No function here has a direct E8 call site, an E9 tail jump, or an
LEA reference anywhere in .text (whole-.text scans): they are
reached only through the vtable slots above.

The census `source_body_sha256` values for the three compare
functions and the Compare thunk are reproduced exactly by hashing
each body with its relocation fields zeroed (see
`RELOCATION_OFFSETS` below). The four destructors carry kind-42
(R_X86_64_GOTPCRELX, relaxed `mov` -> `lea` rewrite) relocations
in addition to the call rel32s, so their source hashes are NOT
reproduced by plain zeroing; only the `target_body_sha256` bind
(which matches exactly for all eight) is claimed for them, and
`raw_equal` false is explained by the recorded relocations. The
FDE ranges match the census ranges exactly and were re-checked
against `objdump --dwarf=frames` pc ranges.

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

# Timestamp size: the U64 timestamp suffix, read by Compare from the
# object field at +0x28 (factory stores 8 there, see 0x61bea64).
TS_SIZE = 8

# (name, start, end, target_body_sha256).
FUNCTIONS = [
    ("CompareTimestamp", 0x61BD920, 0x61BD946,
     "f73501ca409cc995031497f7083712bd48ae14c440d6d180596eb72d88872ef8"),
    ("Compare", 0x61BDB20, 0x61BDB97,
     "2b7cc1dad8c2805c4e7ff60d1487072f62e07897f945006482510bb5c90780aa"),
    ("CompareWithoutTimestamp", 0x61BDE00, 0x61BDE5F,
     "0dd18014e1551d62de2f292d86abc7e0c4dc2dba10509d29bde2bce106591968"),
    ("CompareThunk", 0x61BDE60, 0x61BDED7,
     "94ada2c8cdf065aedc1470ab520a400baed474f0877ccdf31600f944206edc25"),
    ("DestructorD0", 0x61BE120, 0x61BE23B,
     "33ef3e926c919da7f2896f2997f5a4ee5ed2a3ebf1f41ec5c2ee75defe7f7bd3"),
    ("DestructorD1", 0x61BE240, 0x61BE35B,
     "2b3332200b6ef7b55dcd9c8432913457bd8e98e1369cd72c36d54a35c3b8c6b0"),
    ("DestructorThunkD0", 0x61BE360, 0x61BE473,
     "a9c2f82e7400d9e828eef348011572c5337eff5637ea38c6197f25337bab6d48"),
    ("DestructorThunkD1", 0x61BE6E0, 0x61BE7FB,
     "c7c2a86c4add966e0d13a531dde5259532535a51039c0c5d39e6aae3023144ee"),
]

# Relocation offsets (4-byte fields) whose zeroing reproduces each
# census source_body_sha256, taken from the census records. None
# means "not reproducible by zeroing": the destructors carry kind-42
# relaxed (mov -> lea) relocations, so only the target hash is
# claimed for them.
RELOCATION_OFFSETS = {
    0x61BD920: (),
    0x61BDB20: (55,),
    0x61BDE00: (54,),
    0x61BDE60: (55,),
    0x61BE120: None,
    0x61BE240: None,
    0x61BE360: None,
    0x61BE6E0: None,
}
SOURCE_BODY_SHA256 = {
    0x61BD920:
        "f73501ca409cc995031497f7083712bd48ae14c440d6d180596eb72d88872ef8",
    0x61BDB20:
        "ae311e78aacf5b8e3bdd4dbdb2a3c4b8dea3fbe63008578fdf495b65969d9db4",
    0x61BDE00:
        "925308d6d82e8340284964e76d64b5d86eefce8a584375876ca774df82412ef2",
    0x61BDE60:
        "b9ea8ae26a24db62e92b1aa0cfd9cc8e6af3d823ea66e036cda64cb43d38b00f",
}

# Vtable (RELATIVE) slots per function, from readelf -r on the binary.
# The wrapper primary vtable has stored vptr 0x64d7278; the secondary
# vtable (offset-to-top -32) has stored vptr 0x64d7370.
VTABLE_SLOTS = {
    0x61BD920: [("u64ts_comparator", 0x64D7278, 0xC8)],
    0x61BDB20: [("u64ts_comparator", 0x64D7278, 0xE0)],
    0x61BDE00: [("u64ts_comparator", 0x64D7278, 0xD0)],
    0x61BDE60: [("u64ts_comparator_secondary", 0x64D7370, 0x10)],
    0x61BE120: [("u64ts_comparator", 0x64D7278, 0x08)],
    0x61BE240: [("u64ts_comparator", 0x64D7278, 0x00)],
    0x61BE360: [("u64ts_comparator_secondary", 0x64D7370, 0x08)],
    0x61BE6E0: [("u64ts_comparator_secondary", 0x64D7370, 0x00)],
}


def _timestamp(key, user_len):
    """Little-endian u64 timestamp stored after the user key."""
    return struct.unpack_from("<Q", key, user_len)[0]


def compare_timestamp(a, b):
    """Transliteration of `CompareTimestamp` (0x61bd920).

    The slices ARE the timestamps: the first 8 bytes of each slice
    data are read as a little-endian u64 and compared ascending.
    """
    ats = struct.unpack_from("<Q", a, 0)[0]
    bts = struct.unpack_from("<Q", b, 0)[0]
    return (ats > bts) - (ats < bts)


def compare_timestamp_model(a, b):
    """Independent model: ascending u64 comparison."""
    return (int.from_bytes(a[:8], "little")
            > int.from_bytes(b[:8], "little")) - (
        int.from_bytes(a[:8], "little")
        < int.from_bytes(b[:8], "little"))


def compare(a, b):
    """Transliteration of `Compare` (0x61bdb20) and its thunk
    (0x61bde60).

    User keys are the slices minus the trailing 8-byte timestamp;
    raw memcmp value, then the -1/0/+1 length tiebreak; equal user
    keys fall through to the timestamps, compared DESCENDING (the
    larger timestamp sorts first).
    """
    ua, ub = a[:-TS_SIZE], b[:-TS_SIZE]
    n = min(len(ua), len(ub))
    for i in range(n):
        if ua[i] != ub[i]:
            return ua[i] - ub[i]
    if len(ua) < len(ub):
        return -1
    if len(ua) > len(ub):
        return 1
    ats = _timestamp(a, len(ua))
    bts = _timestamp(b, len(ub))
    if ats < bts:
        return 1
    if ats > bts:
        return -1
    return 0


def compare_model(a, b):
    """Independent model: bytewise user-key order, then timestamps
    descending."""
    ua, ub = a[:-TS_SIZE], b[:-TS_SIZE]
    if ua != ub:
        n = min(len(ua), len(ub))
        for i in range(n):
            if ua[i] != ub[i]:
                return ua[i] - ub[i]
        return (len(ua) > len(ub)) - (len(ua) < len(ub))
    ats = int.from_bytes(a[len(ua):], "little")
    bts = int.from_bytes(b[len(ub):], "little")
    return (bts > ats) - (bts < ats)


def compare_without_timestamp(a, a_has_ts, b, b_has_ts):
    """Transliteration of `CompareWithoutTimestamp` (0x61bde00).

    Strips the trailing 8 bytes from a slice only when its flag is
    set, then a plain bytewise compare (raw memcmp value, -1/0/+1
    length tiebreak). The timestamps are never compared.
    """
    if a_has_ts:
        a = a[:-TS_SIZE]
    if b_has_ts:
        b = b[:-TS_SIZE]
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return a[i] - b[i]
    return (len(a) > len(b)) - (len(a) < len(b))


def compare_without_timestamp_model(a, a_has_ts, b, b_has_ts):
    """Independent model: strip flagged timestamps, plain compare."""
    ua = a[:-TS_SIZE] if a_has_ts else a
    ub = b[:-TS_SIZE] if b_has_ts else b
    if ua != ub:
        n = min(len(ua), len(ub))
        for i in range(n):
            if ua[i] != ub[i]:
                return ua[i] - ub[i]
        return (len(ua) > len(ub)) - (len(ua) < len(ub))
    return 0


def _key_with_ts(rng, user_len, ts=None):
    user = bytes(rng.randrange(256) for _ in range(user_len))
    if ts is None:
        ts = rng.randrange(1 << 64)
    return user + struct.pack("<Q", ts)


def _ts_cases(rng):
    values = [0, 1, 2, (1 << 63) - 1, 1 << 63, (1 << 64) - 2,
              (1 << 64) - 1]
    return values


def generate_cases():
    """2,400 deterministic cases: transliteration vs model."""
    rng = random.Random(20261109)
    cases = []
    index = 0

    def add(kind, **fields):
        nonlocal index
        case = {"kind": kind, "index": index}
        case.update(fields)
        cases.append(case)
        index += 1

    # compare: 800. User keys 0..16 bytes; timestamps random, equal,
    # boundary, and ordered pairs to pin the descending rule.
    ts_pool = _ts_cases(rng)
    for _ in range(800):
        la = rng.choice([0, 0, 1, 2, 3, 5, 8, 12, 16])
        lb = rng.choice([0, 0, 1, 2, 3, 5, 8, 12, 16])
        style = rng.randrange(6)
        if style == 0:
            # Equal user keys, timestamps decide.
            user = bytes(rng.randrange(256) for _ in range(la))
            ta = rng.choice(ts_pool + [rng.randrange(1 << 64)])
            tb = rng.choice(ts_pool + [rng.randrange(1 << 64)])
            a = user + struct.pack("<Q", ta)
            b = user + struct.pack("<Q", tb)
        elif style == 1:
            # Shared prefix, differ at one byte.
            n = min(la, lb)
            base = bytearray(rng.randrange(256) for _ in range(n))
            a_user = bytes(base)
            b_user = bytes(base)
            if n:
                i = rng.randrange(n)
                b_list = bytearray(b_user)
                b_list[i] = rng.randrange(256)
                b_user = bytes(b_list)
            a = a_user + bytes(
                rng.randrange(256) for _ in range(max(0, la - n)))
            b = b_user + bytes(
                rng.randrange(256) for _ in range(max(0, lb - n)))
            a += struct.pack("<Q", rng.randrange(1 << 64))
            b += struct.pack("<Q", rng.randrange(1 << 64))
        elif style == 2:
            # One user key a prefix of the other.
            n = min(la, lb)
            base = bytes(rng.randrange(256) for _ in range(n))
            a = base + bytes(rng.randrange(256)
                             for _ in range(la - n))
            b = base + bytes(rng.randrange(256)
                             for _ in range(lb - n))
            a += struct.pack("<Q", rng.randrange(1 << 64))
            b += struct.pack("<Q", rng.randrange(1 << 64))
        elif style == 3:
            # Identical keys (out 0).
            a = _key_with_ts(rng, la)
            b = a
        elif style == 4:
            # Extreme user bytes.
            a = bytes([rng.choice([0, 0xFF]) for _ in range(la)])
            b = bytes([rng.choice([0, 0xFF]) for _ in range(lb)])
            a += struct.pack("<Q", rng.choice(ts_pool))
            b += struct.pack("<Q", rng.choice(ts_pool))
        else:
            a = _key_with_ts(rng, la)
            b = _key_with_ts(rng, lb)
        add("compare", a_hex=a.hex(), b_hex=b.hex(),
            out=compare_model(a, b))

    # compare_timestamp: 400. Raw 8-byte timestamps.
    for _ in range(400):
        style = rng.randrange(4)
        if style == 0:
            ta = rng.choice(ts_pool)
            tb = rng.choice(ts_pool)
        elif style == 1:
            ta = tb = rng.choice(ts_pool + [rng.randrange(1 << 64)])
        elif style == 2:
            ta = rng.randrange(1 << 64)
            tb = ta ^ (1 << rng.randrange(64))
        else:
            ta = rng.randrange(1 << 64)
            tb = rng.randrange(1 << 64)
        a = struct.pack("<Q", ta)
        b = struct.pack("<Q", tb)
        add("compare_timestamp", a_hex=a.hex(), b_hex=b.hex(),
            out=compare_timestamp_model(a, b))

    # compare_without_timestamp: 800. All four flag combinations;
    # flagged slices are at least 8 bytes long (the body's
    # precondition: it subtracts 8 without a check).
    for _ in range(800):
        fa = rng.randrange(2)
        fb = rng.randrange(2)
        la = rng.choice([0, 1, 2, 5, 8, 9, 12, 16])
        lb = rng.choice([0, 1, 2, 5, 8, 9, 12, 16])
        if fa:
            la = max(la, 8)
        if fb:
            lb = max(lb, 8)
        style = rng.randrange(5)
        if style == 0:
            # Same user key, different timestamps: must compare 0
            # when both flags strip, else the raw tail decides.
            user = bytes(rng.randrange(256) for _ in range(
                min(la if fa else la, lb if fb else lb)))
            a = user + bytes(rng.randrange(256)
                             for _ in range(la - len(user)))
            b = user + bytes(rng.randrange(256)
                             for _ in range(lb - len(user)))
            if fa:
                a += struct.pack("<Q", rng.randrange(1 << 64))
            if fb:
                b += struct.pack("<Q", rng.randrange(1 << 64))
            # Rebuild so the user parts really agree when stripped.
            ua = a[:-TS_SIZE] if fa else a
            ub = b[:-TS_SIZE] if fb else b
            if len(ua) != len(ub):
                # Pad the shorter user part to the same bytes.
                m = min(len(ua), len(ub))
                ua = ua[:m] + bytes(rng.randrange(256)
                                    for _ in range(len(ua) - m))
                ub = ub[:m] + bytes(rng.randrange(256)
                                    for _ in range(len(ub) - m))
                a = ua + (a[len(ua):] if fa else b"")
                b = ub + (b[len(ub):] if fb else b"")
                if fa and len(a) < 8:
                    a += struct.pack("<Q", 0)
                if fb and len(b) < 8:
                    b += struct.pack("<Q", 0)
        elif style == 1:
            a = bytes(rng.randrange(256) for _ in range(la))
            b = bytes(rng.randrange(256) for _ in range(lb))
        elif style == 2:
            a = b = bytes(rng.randrange(256) for _ in range(la))
            if fb and lb != la:
                b = bytes(rng.randrange(256) for _ in range(lb))
        elif style == 3:
            a = bytes([rng.choice([0, 0xFF]) for _ in range(la)])
            b = bytes([rng.choice([0, 0xFF]) for _ in range(lb)])
        else:
            n = min(la, lb)
            base = bytes(rng.randrange(256) for _ in range(n))
            a = base + bytes(rng.randrange(256)
                             for _ in range(la - n))
            b = base + bytes(rng.randrange(256)
                             for _ in range(lb - n))
        add("compare_without_timestamp", a_hex=a.hex(),
            b_hex=b.hex(), flag_a=fa, flag_b=fb,
            out=compare_without_timestamp_model(a, fa, b, fb))

    # compare_thunk: 400, same behaviour as compare (the thunk only
    # adjusts the `this` offset for the timestamp-size field).
    for _ in range(400):
        la = rng.choice([0, 1, 2, 3, 5, 8, 12, 16])
        lb = rng.choice([0, 1, 2, 3, 5, 8, 12, 16])
        if rng.randrange(2):
            user = bytes(rng.randrange(256) for _ in range(la))
            a = user + struct.pack("<Q", rng.randrange(1 << 64))
            b = user + struct.pack("<Q", rng.randrange(1 << 64))
            if lb != la:
                b = (bytes(rng.randrange(256) for _ in range(lb))
                     + struct.pack("<Q", rng.randrange(1 << 64)))
        else:
            a = _key_with_ts(rng, la)
            b = _key_with_ts(rng, lb)
        add("compare_thunk", a_hex=a.hex(), b_hex=b.hex(),
            out=compare_model(a, b))
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

    (All eight functions have none; the method is validated against
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
        elif kind == "compare_timestamp":
            got = compare_timestamp(a, b)
            want = case["out"]
        elif kind == "compare_without_timestamp":
            got = compare_without_timestamp(
                a, case["flag_a"], b, case["flag_b"])
            want = case["out"]
        elif kind == "compare_thunk":
            got = compare(a, b)
            want = case["out"]
        else:  # pragma: no cover
            raise ValueError("unknown kind %r" % kind)
        if got != want:
            mismatches += 1
            print("mismatch: %r got %r want %r" % (case, got, want))
    checks = {
        "compare_timestamp_descending": compare(
            b"abc" + struct.pack("<Q", 5),
            b"abc" + struct.pack("<Q", 3)),
        "compare_timestamp_ascending": compare(
            b"abc" + struct.pack("<Q", 3),
            b"abc" + struct.pack("<Q", 5)),
        "compare_timestamp_equal": compare(
            b"abc" + struct.pack("<Q", 7),
            b"abc" + struct.pack("<Q", 7)),
        "compare_memcmp_value": compare(
            b"a\x00" + struct.pack("<Q", 9),
            b"a\xff" + struct.pack("<Q", 9)),
        "compare_timestamp_fn": compare_timestamp(
            struct.pack("<Q", 5), struct.pack("<Q", 3)),
        "compare_without_timestamp_strips": compare_without_timestamp(
            b"key" + struct.pack("<Q", 1), 1,
            b"key" + struct.pack("<Q", 2), 1),
        "compare_without_timestamp_keeps": compare_without_timestamp(
            b"key" + struct.pack("<Q", 1), 0,
            b"key" + struct.pack("<Q", 2), 0),
    }
    expected = {
        "compare_timestamp_descending": -1,
        "compare_timestamp_ascending": 1,
        "compare_timestamp_equal": 0,
        "compare_memcmp_value": -255,
        "compare_timestamp_fn": 1,
        "compare_without_timestamp_strips": 0,
        "compare_without_timestamp_keeps": -1,
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
    parser.add_argument("--binary", default="artifacts/node/115/hl-node")
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
            elif kind == "compare_timestamp":
                good = compare_timestamp(a, b) == case["out"]
            elif kind == "compare_without_timestamp":
                good = (compare_without_timestamp(
                    a, case["flag_a"], b, case["flag_b"])
                    == case["out"])
            elif kind == "compare_thunk":
                good = compare(a, b) == case["out"]
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
                 "scope": "node #115 u64ts comparator wrapper"}
                for name, s, e, t in FUNCTIONS
            ],
            "cases": counts,
            "total_cases": len(cases),
            "mismatches": mismatches,
            "check_values": {
                "compare_timestamp_descending": compare(
                    b"abc" + struct.pack("<Q", 5),
                    b"abc" + struct.pack("<Q", 3)),
                "compare_timestamp_ascending": compare(
                    b"abc" + struct.pack("<Q", 3),
                    b"abc" + struct.pack("<Q", 5)),
                "compare_timestamp_equal": compare(
                    b"abc" + struct.pack("<Q", 7),
                    b"abc" + struct.pack("<Q", 7)),
                "compare_memcmp_value": compare(
                    b"a\x00" + struct.pack("<Q", 9),
                    b"a\xff" + struct.pack("<Q", 9)),
                "compare_timestamp_fn": compare_timestamp(
                    struct.pack("<Q", 5), struct.pack("<Q", 3)),
                "compare_without_timestamp_strips": (
                    compare_without_timestamp(
                        b"key" + struct.pack("<Q", 1), 1,
                        b"key" + struct.pack("<Q", 2), 1)),
                "compare_without_timestamp_keeps": (
                    compare_without_timestamp(
                        b"key" + struct.pack("<Q", 1), 0,
                        b"key" + struct.pack("<Q", 2), 0)),
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
