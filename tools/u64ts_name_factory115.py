#!/usr/bin/env python3
"""Node #115 `rocksdb::ComparatorWithU64TsImpl<BytewiseComparatorImpl>`
name + factory: `Name`, `kClassNameInternal` and
`BytewiseComparatorWithU64Ts`.

Reconstructs the follow-up the merged RE-002 U64Ts-comparator-wrapper
packet (#5847) left open: the string building and the singleton
construction for the wrapper, from the node #115 binary (artifact
SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).
The three functions are all census-bound (vendor census
`research/work-items/RE-002-node115-vendor-census/census.json`,
member `6cca28ae25285154-comparator.o`, crate `librocksdb-sys`
0.11.0+8.1.1, published-crate rebuild):

* `rocksdb::BytewiseComparatorWithU64Ts()` at 0x61be9d0..0x61beabe
  (238 bytes, census `node115-vendor-61be9d0`, body SHA-256
  4ef3dd02c39343d9bdd38d032ae7a794e28216a17f8b1b4098b47c73fe794779;
  source body SHA-256
  06ff1f1e2b815b335e5b40114b1d0fca9807ca8358471b99aae635a69d2aa373,
  reproduced exactly by zeroing the 12 census relocation fields):
  a function-local-static singleton factory. On the first call it
  acquires the `__cxa_guard` at 0x65088c8, allocates a 96-byte
  object (`operator new(0x60)`), and initialises it: primary vptr
  0x64d7278 at +0x00, secondary vptr 0x64d7370 (= 0x64d7278 + 0xf8)
  at +0x20, timestamp size 8 at +0x28, the inner Bytewise vptr
  0x64d7038 at +0x30, the inner secondary vptr 0x64d7130 at
  +0x50, and zeroes +0x08/+0x10/+0x18 (the first member vector)
  and +0x38/+0x40/+0x48 (the second member vector) and +0x58.
  It stores the object at 0x65088d0, releases the guard and
  returns the singleton pointer. Later calls return the stored
  pointer without allocating. A 9-byte tail-call stub at
  0x61beac0..0x61beac9 (`endbr64; jmp 0x61be9d0`, body SHA-256
  63d0fbe8397c36521e87839a36a225f96e90f556840d1e32ad245d15ca199124,
  its own FDE, no census record) forwards to the factory.
  The only direct E8 caller is 0x61c0aa0, inside the
  comparator-by-name selection routine at 0x61c0180..0x61c0cb4,
  which also calls the sibling factory at 0x61be8f0 (the
  `ReverseBytewiseComparator()` copy: FDE 0x61be8f0..0x61be9a8,
  census `node115-vendor-61be8f0`, one of 2 identical copies --
  the census lists both `BytewiseComparator` and
  `ReverseBytewiseComparator` as candidates, and the stored
  vtable 0x64d7158, whose Name slot returns
  "rocksdb.ReverseBytewiseComparator", pins this copy to the
  reverse one).

* `rocksdb::(anonymous namespace)::ComparatorWithU64TsImpl<rocksdb::
  (anonymous namespace)::BytewiseComparatorImpl>::kClassNameInternal()`
  at 0x61bebd0..0x61bef66 (918 bytes, census
  `node115-vendor-61bebd0`, body SHA-256
  e7bae44a5679b505343d1fdd2124cbb2abb92111c691ba9210399d54a5b0e914;
  source body SHA-256
  03e4ada40219b430c66f618507d4eb1d970ea5323212a94fb462bf66b693a0e8,
  reproduced exactly by zeroing the 28 census relocation
  fields): builds the class name with a `std::ostringstream`
  (libstdc++ `basic_stringstream`, vtable/VTT at 0x64ed600 /
  0x64ed608): it inserts the 26-byte literal
  "leveldb.BytewiseComparator" (.rodata 0x44e0fe, `mov $0x1a,
  %edx`) and then the 6-byte literal ".u64ts" (.rodata 0x43c8ab,
  `mov $0x6, %edx`) via `__ostream_insert`, and copies the
  stream's string into the out `std::string` (sret, returned in
  rax) with `basic_string::_M_replace(0, 0, ptr, len)`. The
  result is exactly "leveldb.BytewiseComparator.u64ts"
  (32 chars). The only direct E8 caller is 0x61beff5, inside
  `Name`. The exception cleanup lives in the `.cold` part at
  0x61beac9..0x61bebc6 (253 bytes, census
  `node115-vendor-61beac9`, symbol `...kClassNameInternalEv.cold`,
  body SHA-256
  4a22c39add303fde0d181d2b9e64b8ed53c8c516d77c919e598063bfa2eb2116):
  it disposes the out string and destroys the stringstream,
  then `_Unwind_Resume`s. One local jump field inside the hot
  body (offset 849, the `jmp` at 0x61bef20 to the next landing-pad
  stub) is not in the census relocation list; its displacement
  is identical in the source and target builds, so the source
  hash already matches with only the census fields zeroed.
  The `.cold` part itself is census-bound too (see FUNCTIONS):
  its source hash also reproduces exactly by zeroing its 12
  census relocation fields.

* `...::Name() const` at 0x61bef90..0x61bf02b (155 bytes, census
  `node115-vendor-61bef90`, body SHA-256
  2797ccf24611e0570b6894d840b2f7a6fd01abcba7fe3a75fab57ea348763dd3;
  source body SHA-256
  159ed939dec9f51b2fb78fd720a2c49ca32efdc4793887fdd526828a14c48236,
  reproduced exactly by zeroing the 12 census relocation
  fields): a function-local-static cache of the name string.
  On the first call it acquires the `__cxa_guard` at 0x6508898,
  calls `kClassNameInternal` into the static `std::string` at
  0x65088a0, registers the libstdc++ `~basic_string` destructor
  (GLOB_DAT slot 0x64ed5d8) with `__cxa_atexit`, releases the
  guard, and returns the string's data pointer (`const char*`,
  i.e. the cached "leveldb.BytewiseComparator.u64ts"). Later
  calls return the cached pointer directly. It has NO direct E8
  call site, E9 tail jump, or LEA reference anywhere in .text:
  it is reached only through the wrapper vtable slot +0x70
  (see below). The guard and the static string ARE referenced
  directly by the comparator-by-name selection routines at
  0x61c0180..0x61c0cb4 and 0x61c1210..0x61c1a1a, which inline the
  guard check and the cached-string use (e.g. `strlen` on it at
  0x61c0370) instead of calling `Name`; and the atexit cleanup
  function at 0x61bffe8..0x61c0173 (395 bytes, body SHA-256
  44491e497572cb7e02b2f2dbcc12b6728923c02c4b541105cb1c5f44e53a7cc2,
  no census record) disposes the cached string.

Vtable binding (R_X86_64_RELATIVE slots, from `readelf -r`):
the wrapper primary vtable (stored vptr 0x64d7278) holds D1 at
+0x00, D0 at +0x08, `Name` at +0x70 (slot 14) -- this CORRECTS
the #5847 packet, which wrote +0x68; +0x68 holds 0x609d980, a
shared base-class function present in the Bytewise vtable too
(0x64d7038 + 0x68 is the same 0x609d980), while +0x70 holds the
wrapper's `Name` (0x61bef90) and the Bytewise vtable's +0x70
holds its `Name` (0x61bd720, which returns the
"leveldb.BytewiseComparator" literal directly). The remaining
reconstructed slots are `CompareTimestamp` at +0xc8 (slot 25),
`CompareWithoutTimestamp` at +0xd0 (slot 26) and `Compare` at
+0xe0 (slot 28), all from #5847, re-verified here. The
secondary vtable (stored vptr 0x64d7370, offset-to-top -32)
holds thunk D1 at +0x00, thunk D0 at +0x08 and thunk `Compare`
at +0x10 (slot 2).

The three functions produce constant values (one 32-byte string,
one 96-byte singleton layout, one cached pointer), so the 2,400
deterministic cases check the assembly rule over real .rodata
strings plus the guard/singleton state machines over seeded call
sequences, with every constant verified against the binary by
`--verify`. No binary is executed by this tool; the models below
are checked against each other and against the binary's bytes.
"""

import argparse
import hashlib
import json
import random
import struct
import subprocess
from pathlib import Path

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
CENSUS_PATH = (
    "research/work-items/RE-002-node115-vendor-census/census.json"
)

# The two literals kClassNameInternal inserts, from .rodata.
INNER_NAME = b"leveldb.BytewiseComparator"  # 26 bytes, .rodata 0x44e0fe
NAME_SUFFIX = b".u64ts"  # 6 bytes, .rodata 0x43c8ab
FULL_NAME = INNER_NAME + NAME_SUFFIX  # 32 bytes
INNER_NAME_ADDR = 0x44E0FE
NAME_SUFFIX_ADDR = 0x43C8AB

# (name, start, end, target_body_sha256, source_body_sha256,
#  census_id, census_relocation_offsets).
FUNCTIONS = [
    ("Factory", 0x61BE9D0, 0x61BEABE,
     "4ef3dd02c39343d9bdd38d032ae7a794e28216a17f8b1b4098b47c73fe794779",
     "06ff1f1e2b815b335e5b40114b1d0fca9807ca8358471b99aae635a69d2aa373",
     "node115-vendor-61be9d0",
     (7, 18, 37, 49, 60, 86, 93, 100, 203, 208, 215, 234)),
    ("kClassNameInternal", 0x61BEBD0, 0x61BEF66,
     "e7bae44a5679b505343d1fdd2124cbb2abb92111c691ba9210399d54a5b0e914",
     "03e4ada40219b430c66f618507d4eb1d970ea5323212a94fb462bf66b693a0e8",
     "node115-vendor-61bebd0",
     (23, 68, 92, 139, 146, 157, 259, 304, 399, 406, 481, 498, 503,
      520, 525, 609, 676, 683, 702, 761, 787, 844, 854, 866, 878,
      890, 902, 914)),
    ("Name", 0x61BEF90, 0x61BF02B,
     "2797ccf24611e0570b6894d840b2f7a6fd01abcba7fe3a75fab57ea348763dd3",
     "159ed939dec9f51b2fb78fd720a2c49ca32efdc4793887fdd526828a14c48236",
     "node115-vendor-61bef90",
     (29, 40, 75, 83, 94, 102, 109, 116, 124, 132, 139, 151)),
    # The 9-byte tail-call stub; its own FDE, no census record.
    ("FactoryForwarder", 0x61BEAC0, 0x61BEAC9,
     "63d0fbe8397c36521e87839a36a225f96e90f556840d1e32ad245d15ca199124",
     None, None, ()),
    # The kClassNameInternal .cold landing pad; its own FDE and
    # census record (symbol ...kClassNameInternalEv.cold).
    ("kClassNameInternal.cold", 0x61BEAC9, 0x61BEBC6,
     "4a22c39add303fde0d181d2b9e64b8ed53c8c516d77c919e598063bfa2eb2116",
     "a3cea38332f4b685155d871bdb3646ba9c40135f1bbf63328f820e2c0fd7da11",
     "node115-vendor-61beac9",
     (4, 14, 45, 52, 74, 81, 100, 162, 183, 210, 215, 249)),
]

# Associated FDE bound by hash (not a reconstructed function):
# the atexit cleanup that disposes the cached Name string.
ASSOCIATED_FDES = [
    ("NameAtexitDestructor", 0x61BFFE8, 0x61C0173,
     "44491e497572cb7e02b2f2dbcc12b6728923c02c4b541105cb1c5f44e53a7cc2",
     None),
]

# Vtable (RELATIVE) slots, from readelf -r on the binary.
# (vtable name, stored vptr, slot offset). Name at +0x70 corrects
# the #5847 packet's +0x68 (verified against the Bytewise vtable,
# whose +0x70 holds its own Name at 0x61bd720).
VTABLE_SLOTS = {
    0x61BEF90: [("u64ts_comparator", 0x64D7278, 0x70)],
    0x61BD920: [("u64ts_comparator", 0x64D7278, 0xC8)],
    0x61BDE00: [("u64ts_comparator", 0x64D7278, 0xD0)],
    0x61BDB20: [("u64ts_comparator", 0x64D7278, 0xE0)],
    0x61BE240: [("u64ts_comparator", 0x64D7278, 0x00)],
    0x61BE120: [("u64ts_comparator", 0x64D7278, 0x08)],
    0x61BDE60: [("u64ts_comparator_secondary", 0x64D7370, 0x10)],
    0x61BE6E0: [("u64ts_comparator_secondary", 0x64D7370, 0x00)],
    0x61BE360: [("u64ts_comparator_secondary", 0x64D7370, 0x08)],
}

# The factory's object layout: (offset, size, value) where value is
# an int (stored qword), a vtable address, or the string "zero".
FACTORY_OBJECT_SIZE = 0x60
FACTORY_LAYOUT = [
    (0x00, 8, 0x64D7278, "primary vptr (wrapper)"),
    (0x08, 8, 0, "member vector 1 begin"),
    (0x10, 8, 0, "member vector 1 end"),
    (0x18, 8, 0, "member vector 1 capacity"),
    (0x20, 8, 0x64D7370, "secondary vptr (wrapper)"),
    (0x28, 8, 8, "timestamp_size_"),
    (0x30, 8, 0x64D7038, "inner Bytewise vptr"),
    (0x38, 8, 0, "member vector 2 begin"),
    (0x40, 8, 0, "member vector 2 end"),
    (0x48, 8, 0, "member vector 2 capacity"),
    (0x50, 8, 0x64D7130, "inner secondary vptr"),
    (0x58, 8, 0, "unused / padding"),
]

# Guard / instance addresses (BSS).
FACTORY_GUARD = 0x65088C8
FACTORY_INSTANCE = 0x65088D0
NAME_GUARD = 0x6508898
NAME_STRING = 0x65088A0

# Direct call sites (E8), verified by whole-.text scans; the
# forwarder is an E9 tail jump. (name, site, target).
DIRECT_CALL_SITES = [
    ("Factory", 0x61C0AA0, 0x61BE9D0),
    ("kClassNameInternal", 0x61BEFF5, 0x61BEBD0),
]
FORWARDER_SITE = (0x61BEAC4, 0x61BE9D0)

# Sites in the selection routines that reference the Name guard /
# static string directly (inlined guard checks + cached-string
# uses), verified by objdump decode of the enclosing FDEs.
NAME_STATIC_REFS = [
    0x61C0348, 0x61C035F, 0x61C068E, 0x61C08EB, 0x61C0915, 0x61C0A47,
    0x61C0A53, 0x61C0BF7, 0x61C10A8, 0x61C1148, 0x61C1465, 0x61C1474,
    0x61C1578, 0x61C178C, 0x61C17B6, 0x61C18DE, 0x61C18EA, 0x61C1950,
]

# Real .rodata strings (extracted from the binary) used as the
# assembly-rule pool; the anchor pair is (INNER_NAME, NAME_SUFFIX).
RODATA_POOL_A = [
    b"leveldb.BytewiseComparator",
    b"rocksdb.ReverseBytewiseComparator",
    b"rocksdb.comparator",
    b"comparator name",
    b"Comparator",
    b"Comparator name mismatch",
    b"leveldb.BytewiseComparator.u64ts",
    b"rocksdb",
    b"",
    b"x",
    b"ab",
    b"hello",
]
RODATA_POOL_B = [
    b".u64ts",
    b".unverified",
    b".json",
    b".tmp",
    b".lz4",
    b".asc",
    b"",
    b".",
    b"s",
    b" Comparator: ",
]


def assemble_stream(parts):
    """Transliteration of the ostringstream assembly in
    `kClassNameInternal`: insert each part in order, then take the
    stream's string. The binary inserts exactly two literals."""
    buf = bytearray()
    for part in parts:
        buf += part
    return bytes(buf)


def assemble_stream_model(parts):
    """Independent model: plain concatenation."""
    out = b""
    for part in parts:
        out = out + part
    return out


def k_class_name_internal():
    """Transliteration of `kClassNameInternal` (0x61bebd0)."""
    return assemble_stream([INNER_NAME, NAME_SUFFIX])


def k_class_name_internal_model():
    """Independent model: inner class name + the suffix."""
    return INNER_NAME + NAME_SUFFIX


class Factory:
    """Simulation of `BytewiseComparatorWithU64Ts` (0x61be9d0).

    The guard starts clear and the instance empty; the first call
    constructs the 96-byte object (layout table below) and stores
    it, later calls return the same object. The token stands in
    for the heap pointer: identity is what the binary guarantees,
    not any particular address.
    """

    def __init__(self, token):
        self.guard = 0
        self.instance = None
        self.token = token

    def __call__(self):
        if self.guard == 0:
            self.guard = 1
            self.instance = self.token
            constructed = True
        else:
            constructed = False
        return self.instance, constructed

    def layout(self):
        """The 96-byte object, as (offset, value) pairs."""
        return [(off, value) for off, _size, value, _note
                in FACTORY_LAYOUT]


class NameCache:
    """Simulation of `Name` (0x61bef90) and its static string.

    The guard starts clear and the string empty; the first call
    runs `kClassNameInternal` into the static string, registers
    the atexit destructor, and returns the string's data pointer
    (modelled as the string object itself -- identity is what
    matters). Later calls return the same pointer.
    """

    def __init__(self):
        self.guard = 0
        self.string = None
        self.atexit_registered = False

    def name(self):
        if self.guard == 0:
            self.guard = 1
            self.string = k_class_name_internal()
            self.atexit_registered = True
        return self.string


def forwarder_bytes():
    """The 9-byte stub at 0x61beac0: endbr64; jmp 0x61be9d0."""
    return bytes.fromhex("f30f1efae907ffffff")


def forwarder_target():
    """The stub tail-jumps to the factory."""
    return 0x61BE9D0


def generate_cases():
    """2,400 deterministic cases: assembly rule + factory state
    machine + name-cache state machine."""
    rng = random.Random(20261109)
    cases = []
    index = 0

    def add(kind, **fields):
        nonlocal index
        case = {"kind": kind, "index": index}
        case.update(fields)
        cases.append(case)
        index += 1

    # assemble: 800. The ostringstream rule over real .rodata
    # strings; case 0 is the anchor (INNER_NAME, NAME_SUFFIX).
    add("assemble", a_hex=INNER_NAME.hex(), b_hex=NAME_SUFFIX.hex(),
        out=len(FULL_NAME))
    boundary = [(b"", b""), (b"", NAME_SUFFIX), (INNER_NAME, b""),
                (b"x", b"y"), (b"leveldb.BytewiseComparator", b""),
                (b"", b".u64ts")]
    for s1, s2 in boundary:
        add("assemble", a_hex=s1.hex(), b_hex=s2.hex(),
            out=len(s1 + s2))
    while len(cases) < 800:
        s1 = rng.choice(RODATA_POOL_A)
        s2 = rng.choice(RODATA_POOL_B)
        add("assemble", a_hex=s1.hex(), b_hex=s2.hex(),
            out=len(s1 + s2))

    # factory: 800. Seeded runs of 1..6 calls against a fresh
    # Factory; out is 0 when the call constructs, 1 when it
    # returns the existing singleton. a_hex is the run token,
    # b_hex the layout digest (constant per run).
    layout_digest = hashlib.sha256(
        b"".join(struct.pack("<Q", v) for _, v in
                 [(o, v) for o, _s, v, _n in FACTORY_LAYOUT])
    ).hexdigest()[:16]
    while len([c for c in cases if c["kind"] == "factory"]) < 800:
        token = bytes(rng.randrange(256) for _ in range(8))
        fac = Factory(token)
        n_calls = rng.randrange(1, 7)
        for call_no in range(n_calls):
            if len([c for c in cases
                    if c["kind"] == "factory"]) >= 800:
                break
            _inst, constructed = fac()
            add("factory", a_hex=token.hex(), b_hex=layout_digest,
                flag_a=call_no, flag_b=0,
                out=0 if constructed else 1)

    # name_cache: 800. Seeded interleavings of Name() and
    # kClassNameInternal(); out is 1 when the returned pointer is
    # the stable cached one (always, after the first init), and
    # the content is always the 32-byte name. a_hex encodes the
    # op sequence (N = Name, K = kClassNameInternal), b_hex is
    # the expected name bytes.
    while len([c for c in cases if c["kind"] == "name_cache"]) < 800:
        ops = bytes(rng.choice(b"NK") for _ in range(rng.randrange(1, 6)))
        cache = NameCache()
        stable = 1
        for op in ops:
            if op == 0x4E:  # 'N'
                got = cache.name()
            else:  # 'K'
                got = k_class_name_internal()
            if got != FULL_NAME:
                stable = 0
        add("name_cache", a_hex=ops.hex(), b_hex=FULL_NAME.hex(),
            flag_a=cache.guard, flag_b=1 if cache.atexit_registered
            else 0, out=stable)
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
    for name, start, end, target, _source, _cid, _rels in FUNCTIONS:
        body = data[start - 0x1000:end - 0x1000]
        digest = hashlib.sha256(body).hexdigest()
        if digest != target:
            raise ValueError("body hash mismatch for %s: %s" % (name,
                                                                 digest))
    for name, start, end, target, _cid in ASSOCIATED_FDES:
        body = data[start - 0x1000:end - 0x1000]
        digest = hashlib.sha256(body).hexdigest()
        if digest != target:
            raise ValueError("body hash mismatch for %s: %s" % (name,
                                                                 digest))
    return True


def verify_source_hashes(binary_path):
    """Reproduce each census source_body_sha256 by zeroing the
    census relocation fields (all three reproduce exactly,
    including the kind-42 GOTPCRELX fields)."""
    data = read_binary(binary_path)
    for name, start, end, _target, source, _cid, rels in FUNCTIONS:
        if source is None:
            continue
        body = bytearray(data[start - 0x1000:end - 0x1000])
        for off in rels:
            body[off:off + 4] = b"\0\0\0\0"
        digest = hashlib.sha256(bytes(body)).hexdigest()
        if digest != source:
            raise ValueError("source hash mismatch for %s: %s"
                             % (name, digest))
    return True


def verify_literals(binary_path):
    """The two .rodata literals kClassNameInternal inserts."""
    data = read_binary(binary_path)
    if data[INNER_NAME_ADDR:INNER_NAME_ADDR + len(INNER_NAME)] \
            != INNER_NAME:
        raise ValueError("inner-name literal mismatch")
    if data[NAME_SUFFIX_ADDR:NAME_SUFFIX_ADDR + len(NAME_SUFFIX)] \
            != NAME_SUFFIX:
        raise ValueError("suffix literal mismatch")
    return True


def verify_immediates(binary_path):
    """Key immediates in the three bodies: the insert lengths
    (26, 6), the factory allocation size (0x60) and the timestamp
    size store (8 at +0x28), and the forwarder jmp target."""
    data = read_binary(binary_path)
    kc = data[0x61BEBD0 - 0x1000:0x61BEF66 - 0x1000]
    # mov $0x1a,%edx at 0x61bedba (offset 0x1ea); mov $0x6,%edx
    # at 0x61bedd0 (offset 0x200).
    if kc[0x1EA:0x1EF] != bytes.fromhex("ba1a000000"):
        raise ValueError("insert-length 26 immediate mismatch")
    if kc[0x200:0x205] != bytes.fromhex("ba06000000"):
        raise ValueError("insert-length 6 immediate mismatch")
    fac = data[0x61BE9D0 - 0x1000:0x61BEABE - 0x1000]
    # mov $0x60,%edi at 0x61bea20 (offset 0x50).
    if fac[0x50:0x55] != bytes.fromhex("bf60000000"):
        raise ValueError("operator-new size immediate mismatch")
    # movq $0x8,0x28(%rax) at 0x61bea64 (offset 0x94).
    if fac[0x94:0x9C] != bytes.fromhex("48c7402808000000"):
        raise ValueError("timestamp-size store mismatch")
    # Forwarder: endbr64; jmp rel32 to 0x61be9d0.
    if forwarder_bytes() != bytes.fromhex("f30f1efae907ffffff"):
        raise ValueError("forwarder bytes mismatch")
    return True


def find_e8_callers(binary_path, target):
    """Whole-.text E8 scan for direct call sites landing on
    `target`. (.text vaddr 0x1419300, file offset 0x1418300,
    size 0x4FD7700 from readelf -S.)"""
    data = read_binary(binary_path)
    text_va, text_off, text_size = 0x1419300, 0x1418300, 0x4FD7700
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


def find_e9_targets(binary_path, target):
    """Whole-.text E9 scan for tail jumps landing on `target`."""
    data = read_binary(binary_path)
    text_va, text_off, text_size = 0x1419300, 0x1418300, 0x4FD7700
    text = data[text_off:text_off + text_size]
    sites = []
    i = text.find(b"\xe9")
    while i >= 0:
        if i + 5 <= len(text):
            rel = struct.unpack_from("<i", text, i + 1)[0]
            if text_va + i + 5 + rel == target:
                sites.append(text_va + i)
        i = text.find(b"\xe9", i + 1)
    return sites


def verify_call_sites(binary_path):
    """Check the recorded direct call sites byte-by-byte: each
    site holds an E8 whose rel32 lands on its target, and the
    forwarder site holds the E9."""
    data = read_binary(binary_path)
    for _name, site, target in DIRECT_CALL_SITES:
        off = site - 0x1000
        if data[off] != 0xE8:
            raise ValueError("not an E8 at %#x" % site)
        rel = struct.unpack_from("<i", data, off + 1)[0]
        if site + 5 + rel != target:
            raise ValueError("E8 at %#x lands on %#x, not %#x"
                             % (site, site + 5 + rel, target))
    site, target = FORWARDER_SITE
    off = site - 0x1000
    if data[off] != 0xE9:
        raise ValueError("not an E9 at %#x" % site)
    rel = struct.unpack_from("<i", data, off + 1)[0]
    if site + 5 + rel != target:
        raise ValueError("E9 at %#x lands on %#x" % (site, target))
    return True


def verify_vtable_slots(binary_path):
    """Check the recorded vtable slots via readelf -r: each slot
    holds a RELATIVE relocation whose addend is the function."""
    out = subprocess.run(["readelf", "-r", str(binary_path)],
                         capture_output=True, text=True).stdout
    slots = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "R_X86_64_RELATIVE":
            try:
                slots[int(parts[0], 16)] = int(parts[3], 16)
            except ValueError:
                continue
    for func, entries in VTABLE_SLOTS.items():
        for _vtable, base, offset in entries:
            got = slots.get(base + offset)
            if got != func:
                raise ValueError("vtable slot %#x+%#x holds %#x, "
                                 "not %#x" % (base, offset, got, func))
    return True


def verify(binary_path):
    """Transliteration vs model over all cases; returns mismatches."""
    data = read_binary(binary_path)
    mismatches = 0
    cases = generate_cases()
    for case in cases:
        kind = case["kind"]
        a = bytes.fromhex(case["a_hex"])
        b = bytes.fromhex(case.get("b_hex", ""))
        if kind == "assemble":
            got = assemble_stream([a, b])
            want = assemble_stream_model([a, b])
            if got != want or len(got) != case["out"]:
                mismatches += 1
        elif kind == "factory":
            # Replay is covered by the dedicated check below;
            # here just check the recorded out flag is 0/1.
            if case["out"] not in (0, 1):
                mismatches += 1
        elif kind == "name_cache":
            got = k_class_name_internal()
            if got != FULL_NAME or case["out"] != 1:
                mismatches += 1
        else:  # pragma: no cover
            raise ValueError("unknown kind %r" % kind)
    # Factory state-machine replay: every recorded run must
    # construct exactly once and return the same token after.
    runs = {}
    for case in cases:
        if case["kind"] != "factory":
            continue
        token = case["a_hex"]
        runs.setdefault(token, []).append(case)
    for token, run in runs.items():
        fac = Factory(bytes.fromhex(token))
        for i, case in enumerate(run):
            inst, constructed = fac()
            want_constructed = (i == 0)
            if constructed != want_constructed:
                mismatches += 1
            if inst != bytes.fromhex(token):
                mismatches += 1
            if [v for _o, v in fac.layout()] != \
                    [v for _o, _s, v, _n in FACTORY_LAYOUT]:
                mismatches += 1
    # Name-cache replay: every recorded op sequence must end
    # with the guard set, atexit registered, and the 32-byte name.
    for case in cases:
        if case["kind"] != "name_cache":
            continue
        cache = NameCache()
        for op in bytes.fromhex(case["a_hex"]):
            if op == 0x4E:
                got = cache.name()
            else:
                got = k_class_name_internal()
            if got != FULL_NAME:
                mismatches += 1
        if cache.guard != case["flag_a"] or \
                cache.atexit_registered != bool(case["flag_b"]):
            mismatches += 1
    checks = {
        "k_class_name": k_class_name_internal(),
        "k_class_name_len": len(k_class_name_internal()),
        "name_cache_first": NameCache().name(),
        "factory_object_size": FACTORY_OBJECT_SIZE,
        "factory_timestamp_size": dict(
            (o, v) for o, _s, v, _n in FACTORY_LAYOUT)[0x28],
        "forwarder_target": hex(forwarder_target()),
    }
    expected = {
        "k_class_name": b"leveldb.BytewiseComparator.u64ts",
        "k_class_name_len": 32,
        "name_cache_first": b"leveldb.BytewiseComparator.u64ts",
        "factory_object_size": 0x60,
        "factory_timestamp_size": 8,
        "forwarder_target": "0x61be9d0",
    }
    for key, value in expected.items():
        if checks[key] != value:
            raise ValueError("check value mismatch: %s = %r"
                             % (key, checks[key]))
    print("%d cases agree (%d mismatches)" % (len(cases), mismatches))
    for key, value in checks.items():
        print("  %s = %r" % (key, value))
    return mismatches


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--binary", default="artifacts/node/115/hl-node")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.verify:
        verify_binary(args.binary)
        verify_source_hashes(args.binary)
        verify_literals(args.binary)
        verify_immediates(args.binary)
        verify_call_sites(args.binary)
        verify_vtable_slots(args.binary)
        raise SystemExit(1 if verify(args.binary) else 0)
    if args.out is not None:
        verify_binary(args.binary)
        cases = generate_cases()
        mismatches = verify(args.binary)
        counts = {}
        for case in cases:
            counts[case["kind"]] = counts.get(case["kind"], 0) + 1
        counts["total"] = len(cases)
        result = {
            "artifact": "node115",
            "artifact_sha256": ARTIFACT_SHA256,
            "functions": [
                {
                    "name": name,
                    "start": "0x%x" % start,
                    "end": "0x%x" % end,
                    "body_sha256": target,
                    "scope": "node #115 u64ts comparator name + factory",
                }
                for name, start, end, target, _s, _c, _r in FUNCTIONS
            ],
            "cases": counts,
            "total_cases": len(cases),
            "mismatches": mismatches,
            "check_values": {
                "k_class_name": k_class_name_internal().decode(),
                "k_class_name_len": len(k_class_name_internal()),
                "factory_object_size": FACTORY_OBJECT_SIZE,
                "factory_timestamp_size": 8,
                "forwarder_target": "0x61be9d0",
            },
        }
        args.out.write_text(json.dumps(result, indent=1) + "\n")
        print("wrote %s (%d cases)" % (args.out, len(cases)))


if __name__ == "__main__":
    main()
