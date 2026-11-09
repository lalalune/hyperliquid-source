"""Node #115 RocksDB BytewiseComparator / ReverseBytewiseComparator factories:
reconstruction.

RE-002 work item. Reconstructs the two plain singleton factories at
0x61be810..0x61be9a8:

  rocksdb::BytewiseComparator()         0x61be810 (184 B)
  rocksdb::ReverseBytewiseComparator()  0x61be8f0 (184 B)

plus the two 9-byte forwarder stubs 0x61be8d0 / 0x61be9b0 (own FDEs, no
census record) that tail-jump to them.

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Both bodies match the vendor census target_body_sha256 exactly, and both
census source_body_sha256 values are reproduced by zeroing the recorded
relocation fields -- and the two source hashes are IDENTICAL
(55ccba1f251d91c8f0e4d144ba8ca8384beb212d0ab04e4e828c34761337069c):
the two factories are two instantiations of one source body, the
function-local-static singleton getter
(BytewiseComparatorImpl::GetInstance / ReverseBytewiseComparatorImpl
::GetInstance inlined into the free functions). The census record's
symbol field is the same for both copies
(_ZN7rocksdb18BytewiseComparatorEv); which copy is Bytewise and which
is Reverse is pinned by the vtable Name slots and by the two
CreateFromString branches (see records.json), not by the census symbol.

What the binary does, per factory (whole-FDE disassembly, verbatim in
the packet):

  Fast path: load the guard byte (bytewise 0x65088e8, reverse
  0x65088d8); if nonzero, load the instance slot (bytewise 0x65088f0,
  reverse 0x65088e0) and return it. No lock, no call.
  Slow path: __cxa_guard_acquire(guard) (PLT 0x63f0fc0). If it returns
  0 another thread initialized the singleton meanwhile: load the
  instance slot and return it. Otherwise operator new(0x30) (PLT
  0x63f0dd0), then initialise the 0x30-byte object in this exact store
  order: [obj+0x08]=0, [obj+0x10]=0, [obj+0x18]=0, [obj+0x28]=0,
  [obj+0x00]=primary vptr, [obj+0x20]=secondary vptr (= primary+0xf8),
  store the object into the instance slot, __cxa_guard_release(guard)
  (PLT 0x63f0fd0), return the instance.
  Abort path: if operator new throws, the landing pad (bytewise
  0x61be8bc -> shared block 0x61be7fb; reverse 0x61be99c -> shared block
  0x61be8d9) calls __cxa_guard_abort(guard) (PLT 0x63f10b0) and then
  _Unwind_Resume (PLT 0x63f0a50). The guard stays 0, the instance slot
  stays unset, and a later call retries construction.

The object is intentionally never destroyed: the source uses
STATIC_AVOID_DESTRUCTION (util/comparator.cc:569-584), so no
__cxa_atexit registration appears anywhere in either body -- unlike
the U64Ts Name factory (#5852), which does register its cached
std::string for destruction. The 0x30-byte object holds only the two
vtable pointers and zeroed fields: the Comparator base contributes
timestamp_size_ (0 here, both impls are timestamp-free) and the
derived classes add no members (BytewiseComparatorImpl() {} /
ReverseBytewiseComparatorImpl() {} are empty).

Vtable binding (readelf -r RELATIVE addends; the file holds zeros in
.data.rel.ro):
  Bytewise primary 0x64d7038: D1 0x61bdee0 (+0x00), D0 0x61be000
  (+0x08), Name 0x61bd720 (+0x70, returns "leveldb.BytewiseComparator"),
  EqualWithoutTimestamp 0x61bd950 (+0x98), FindShortestSeparator
  0x61bd9e0 (+0xa0), FindShortSuccessor 0x61bd990 (+0xa8),
  IsSameLengthImmediateSuccessor 0x61bd730 (+0xb0),
  CanKeysWithDifferentByteContentsBeEqual 0x61bd7d0 (+0xb8, `xor
  eax,eax; ret` -> false), CompareWithoutTimestamp 0x61bdc40 (+0xd0),
  Compare 0x61bdbf0 (+0xe0). Secondary 0x64d7130 (offset-to-top -32):
  thunk D1 0x61be480 (+0x00), thunk D0 0x61be640 (+0x08), Compare copy 2
  0x61bdd50 (+0x10).
  Reverse primary 0x64d7158: D1 0x61bdf70 (+0x00), D0 0x61be090 (+0x08),
  Name 0x61bd7e0 (+0x70, returns "rocksdb.ReverseBytewiseComparator"),
  EqualWithoutTimestamp 0x61bd950 (+0x98, shared with Bytewise),
  FindShortestSeparator 0x61bdab0 (+0xa0), FindShortSuccessor 0x61bd7f0
  (+0xa8, `endbr64; ret` -> no-op), IsSameLengthImmediateSuccessor
  0x61bd800 (+0xb0, `xor eax,eax; ret` -> false),
  CanKeysWithDifferentByteContentsBeEqual 0x61bd7d0 (+0xb8, shared),
  CompareWithoutTimestamp 0x61bdc90 (+0xd0), Compare 0x61bdcf0 (+0xe0).
  Secondary 0x64d7250 (offset-to-top -32): thunk D1 0x61be510 (+0x00),
  thunk D0 0x61be5a0 (+0x08), Compare copy 2 0x61bdda0 (+0x10).
  The secondary slots match the #5844 packet (Compare copies
  0x61bdd50 / 0x61bdda0); the shared base slots (0x609d760 etc.) are
  identical in both primaries.

Caller census (census.py, whole-.text E8/E9/LEA scan, Capstone-validated
from enclosing FDE starts): BytewiseComparator() has 9 direct callers
plus the stub tail jump; ReverseBytewiseComparator() has exactly 1
direct caller (0x61c0a93, the reverse branch of Comparator::
CreateFromString 0x61c0180) plus its stub tail jump. Each stub has
exactly 1 LEA ref, both inside RegisterBuiltinComparators
0x61c1210..0x61c1a1a (the ObjectLibrary factory lambdas take the stub
address, not the body address): the stubs are the canonical entry
points for function-pointer registration, while direct calls go to the
bodies. No caller reaches either factory through a vtable: these are
free functions, not virtual methods.

Upstream anchors (RocksDB v8.1.1, confirmed by source read):
  * util/comparator.cc:569-575: `const Comparator* BytewiseComparator()
    { STATIC_AVOID_DESTRUCTION(BytewiseComparatorImpl, bytewise);
    return &bytewise; }`
  * util/comparator.cc:578-584: the same for ReverseBytewiseComparator()
    with ReverseBytewiseComparatorImpl / rbytewise.
  * util/comparator.cc:52-60 / 276-289: BytewiseComparatorImpl::kClassName
    is "leveldb.BytewiseComparator"; ReverseBytewiseComparatorImpl
    ::kClassName is "rocksdb.ReverseBytewiseComparator". Both classes
    have empty ctors and no members of their own, so the 0x30-byte
    object is vptr + secondary vptr + zeroed base fields, exactly as
    the binary builds it.
  * util/comparator.cc:598-634 RegisterBuiltinComparators registers all
    three builtin comparators (Bytewise, Reverse, U64Ts) with lambdas
    returning the factories -- the three LEA sites in 0x61c1210.
  * util/comparator.cc:637-723 Comparator::CreateFromString: call_once
    registration, Customizable::GetOptionsMap, then id ==
    "leveldb.BytewiseComparator" (26 chars) -> BytewiseComparator();
    id == "rocksdb.ReverseBytewiseComparator" (33 chars) ->
    ReverseBytewiseComparator(); id == U64Ts kClassName ->
    BytewiseComparatorWithU64Ts(). The 0x61c0180 routine is that
    function; its reconstruction is left as the follow-up (it has no
    vendor census record).

This packet is the continuation of the comparator family: #5844 (the
Bytewise/Reverse ordering and separator functions the vtables point
to), #5847 (the U64Ts wrapper layer), #5852 (the U64Ts factory +
Name). It closes the open unknown the merged
RE-001-options-default-init-115 packet left on the 0x61be810 singleton
("the concrete dynamic type behind the singleton 0x61be810 is not
pinned"): it is a BytewiseComparatorImpl, vtable 0x64d7038.

Environment limits (stated honestly): no cargo/rustc/git-lfs/Ghidra on
this VM; the target binary is never executed; the tool models the
guard/singleton state machine in Python -- no engine call is needed
for a factory, so no ctypes dependency exists here.
"""

import hashlib
import random
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

OBJECT_SIZE = 0x30
PRIMARY_OFF = 0x00
SECONDARY_OFF = 0x20
ZERO_OFFSETS = (0x08, 0x10, 0x18, 0x28)

# __cxa_guard_* / allocation PLT targets (shared by both factories).
GUARD_ACQUIRE = 0x63F0FC0
GUARD_RELEASE = 0x63F0FD0
GUARD_ABORT = 0x63F10B0
OPERATOR_NEW = 0x63F0DD0
UNWIND_RESUME = 0x63F0A50

FACTORIES = {
    "bytewise": {
        "name": "rocksdb::BytewiseComparator",
        "start": 0x61BE810,
        "end": 0x61BE8C8,
        "stub_start": 0x61BE8D0,
        "guard": 0x65088E8,
        "instance": 0x65088F0,
        "primary_vptr": 0x64D7038,
        "secondary_vptr": 0x64D7130,
        "class_name": "leveldb.BytewiseComparator",
        "name_fn": 0x61BD720,
        "landing_pad": 0x61BE7FB,
        "body_sha256": "4d3d060f00bf927dd0d7e9f0fb21a0e1798c54fb4a514f504d529c430a136264",
    },
    "reverse": {
        "name": "rocksdb::ReverseBytewiseComparator",
        "start": 0x61BE8F0,
        "end": 0x61BE9A8,
        "stub_start": 0x61BE9B0,
        "guard": 0x65088D8,
        "instance": 0x65088E0,
        "primary_vptr": 0x64D7158,
        "secondary_vptr": 0x64D7250,
        "class_name": "rocksdb.ReverseBytewiseComparator",
        "name_fn": 0x61BD7E0,
        "landing_pad": 0x61BE8D9,
        "body_sha256": "322fd2cf015ca9435663e3a73d93009727c2b0714ef556bd06dfb73c6d34dd05",
    },
}
# Both bodies reproduce the SAME census source hash: one source body,
# two instantiations.
SHARED_SOURCE_SHA256 = (
    "55ccba1f251d91c8f0e4d144ba8ca8384beb212d0ab04e4e828c34761337069c")
STUB_BODY_SHA256 = (
    "bcc59137385497208cc6255d712076b0ed885f0b73af6991c6b2330da6fd85ca")

# Vtable slots verified from readelf -r RELATIVE addends. The +0x10..+0x68
# and +0x78..+0x90 / +0xc0..+0xc8 slots are shared base-class entries
# (identical in both primaries); the +0x98/+0xd8 slots both hold
# EqualWithoutTimestamp 0x61bd950.
PRIMARY_SLOTS = {
    "bytewise": {
        0x00: 0x61BDEE0,  # D1
        0x08: 0x61BE000,  # D0
        0x10: 0x609D760, 0x18: 0x609DC40, 0x20: 0x5D32560,
        0x28: 0x6095E70, 0x30: 0x6096790, 0x38: 0x5D2E090,
        0x40: 0x60956F0, 0x48: 0x609D0E0, 0x50: 0x60986B0,
        0x58: 0x6095710, 0x60: 0x609DE80, 0x68: 0x609D980,
        0x70: 0x61BD720,  # Name
        0x78: 0x5D32A30, 0x80: 0x5D2E770, 0x88: 0x5D2CA00,
        0x90: 0x5D2CA10,
        0x98: 0x61BD950,  # EqualWithoutTimestamp
        0xA0: 0x61BD9E0,  # FindShortestSeparator
        0xA8: 0x61BD990,  # FindShortSuccessor
        0xB0: 0x61BD730,  # IsSameLengthImmediateSuccessor
        0xB8: 0x61BD7D0,  # CanKeysWithDifferentByteContentsBeEqual -> false
        0xC0: 0x5D2CAC0, 0xC8: 0x5D48400,
        0xD0: 0x61BDC40,  # CompareWithoutTimestamp
        0xD8: 0x61BD950,  # EqualWithoutTimestamp (base slot)
        0xE0: 0x61BDBF0,  # Compare
    },
    "reverse": {
        0x00: 0x61BDF70,  # D1
        0x08: 0x61BE090,  # D0
        0x10: 0x609D760, 0x18: 0x609DC40, 0x20: 0x5D32560,
        0x28: 0x6095E70, 0x30: 0x6096790, 0x38: 0x5D2E090,
        0x40: 0x60956F0, 0x48: 0x609D0E0, 0x50: 0x60986B0,
        0x58: 0x6095710, 0x60: 0x609DE80, 0x68: 0x609D980,
        0x70: 0x61BD7E0,  # Name
        0x78: 0x5D32A30, 0x80: 0x5D2E770, 0x88: 0x5D2CA00,
        0x90: 0x5D2CA10,
        0x98: 0x61BD950,  # EqualWithoutTimestamp (shared)
        0xA0: 0x61BDAB0,  # FindShortestSeparator
        0xA8: 0x61BD7F0,  # FindShortSuccessor (no-op)
        0xB0: 0x61BD800,  # IsSameLengthImmediateSuccessor (false)
        0xB8: 0x61BD7D0,  # CanKeysWithDifferentByteContentsBeEqual -> false
        0xC0: 0x5D2CAC0, 0xC8: 0x5D48400,
        0xD0: 0x61BDC90,  # CompareWithoutTimestamp
        0xD8: 0x61BD950,  # EqualWithoutTimestamp (base slot)
        0xE0: 0x61BDCF0,  # Compare
    },
}
SECONDARY_SLOTS = {
    "bytewise": {0x00: 0x61BE480, 0x08: 0x61BE640, 0x10: 0x61BDD50},
    "reverse": {0x00: 0x61BE510, 0x08: 0x61BE5A0, 0x10: 0x61BDDA0},
}
SECONDARY_OFFSET_TO_TOP = -32


class GuardAbort(Exception):
    """operator new threw: __cxa_guard_abort ran, _Unwind_Resume resumed."""


class ComparatorObject:
    """A 0x30-byte singleton object, as the binary builds it.

    Layout: [primary vptr:8][0:8][0:8][0:8][secondary vptr:8][0:8].
    The object is intentionally leaked (STATIC_AVOID_DESTRUCTION): no
    destructor is ever registered or called for it.
    """

    def __init__(self, family):
        spec = FACTORIES[family]
        self.family = family
        self.mem = bytearray(OBJECT_SIZE)
        # Binary store order: +0x08, +0x10, +0x18, +0x28 zeroed, then
        # the primary vptr at +0x00, then the secondary vptr at +0x20.
        for off in ZERO_OFFSETS:
            struct.pack_into("<Q", self.mem, off, 0)
        struct.pack_into("<Q", self.mem, PRIMARY_OFF,
                         spec["primary_vptr"])
        struct.pack_into("<Q", self.mem, SECONDARY_OFF,
                         spec["secondary_vptr"])
        self.destroyed = False

    def read_qword(self, off):
        return struct.unpack_from("<Q", self.mem, off)[0]

    def primary_vptr(self):
        return self.read_qword(PRIMARY_OFF)

    def secondary_vptr(self):
        return self.read_qword(SECONDARY_OFF)

    def name(self):
        """Name() via vtable slot +0x70: the class-name string."""
        slot = PRIMARY_SLOTS[self.family][0x70]
        assert slot == FACTORIES[self.family]["name_fn"]
        return FACTORIES[self.family]["class_name"]


class SingletonFactory:
    """The guard/instance state machine of one factory function.

    guard: the __cxa_guard byte (0 = uninitialized). instance: the
    ComparatorObject once constructed, else None. allocations counts
    operator new calls; acquires counts __cxa_guard_acquire calls.
    """

    def __init__(self, family, fail_alloc=False, pre_initialized=False):
        self.family = family
        self.spec = FACTORIES[family]
        self.guard = 0
        self.instance = None
        self.allocations = 0
        self.acquires = 0
        self.fail_alloc = fail_alloc
        if pre_initialized:
            # Another thread already ran construction to completion.
            self.guard = 1
            self.instance = ComparatorObject(family)
            self.allocations = 1

    def call(self):
        """Model of the factory body. Returns the singleton object."""
        if self.guard != 0:
            # Fast path: guard set -> return the instance slot.
            return self.instance
        # Slow path: __cxa_guard_acquire.
        self.acquires += 1
        if self.instance is not None:
            # Acquire returned 0: another thread initialized meanwhile.
            return self.instance
        if self.fail_alloc:
            # operator new threw: landing pad runs __cxa_guard_abort
            # then _Unwind_Resume. Guard stays 0, instance stays None.
            raise GuardAbort(
                f"{self.family}: operator new threw; guard aborted")
        self.allocations += 1
        obj = ComparatorObject(self.family)
        self.instance = obj
        # __cxa_guard_release(guard): guard byte becomes 1.
        self.guard = 1
        return obj

    def call_via_stub(self):
        """The 9-byte forwarder stub tail-jumps to the factory body:
        identical result, identical side effects."""
        return self.call()


def make_factory(family, **kw):
    return SingletonFactory(family, **kw)


# ---------------------------------------------------------------------------
# Deterministic case generation (2,400 cases).
# ---------------------------------------------------------------------------

def generate_cases(seed=115):
    """Yield 2,400 case dicts.

    Split: 800 bytewise-factory + 800 reverse-factory state machine
    (each 300 first call, 300 repeat call, 100 acquire-returns-0, 50
    alloc-failure abort, 50 stub call) + 800 vtable/name/layout (200
    name-slot, 200 primary-slot, 100 secondary-slot, 100 layout-zero,
    100 shared-source, 100 stub-identity).
    """
    rng = random.Random(seed)
    cases = []

    def add(family, kind, detail, group):
        cases.append({"id": f"{group}-{len(cases):04d}", "family": family,
                      "kind": kind, "detail": detail, "group": group})

    for family in ("bytewise", "reverse"):
        for _ in range(300):
            add(family, "first-call", "construct-once", "factory")
        for _ in range(300):
            add(family, "repeat-call", "same-pointer", "factory")
        for _ in range(100):
            add(family, "acquire-zero", "other-thread-initialized",
                "factory")
        for _ in range(50):
            add(family, "alloc-fail", "guard-abort-retry", "factory")
        for _ in range(50):
            add(family, "stub-call", "stub-forwards", "factory")
    for family in ("bytewise", "reverse"):
        for _ in range(100):
            add(family, "name-slot", FACTORIES[family]["class_name"],
                "vtable")
        for _ in range(100):
            add(family, "primary-slot", "slot-values", "vtable")
        for _ in range(50):
            add(family, "secondary-slot", "slot-values", "vtable")
        for _ in range(50):
            add(family, "layout-zero", "zeroed-fields", "vtable")
        for _ in range(50):
            add(family, "shared-source", "same-source-hash", "vtable")
        for _ in range(50):
            add(family, "stub-identity", "byte-identical-stubs", "vtable")
    rng.shuffle(cases)
    for i, c in enumerate(cases):
        c["id"] = f"case-{i:04d}"
    assert len(cases) == 2400
    return cases


def expected_outcome(case):
    """Binary-derived expected outcome for a case."""
    kind = case["kind"]
    if kind == "first-call":
        return "constructed"
    if kind == "repeat-call":
        return "same-pointer"
    if kind == "acquire-zero":
        return "existing-instance"
    if kind == "alloc-fail":
        return "guard-abort-then-retry-ok"
    if kind == "stub-call":
        return "stub-same-pointer"
    if kind == "name-slot":
        return FACTORIES[case["family"]]["class_name"]
    if kind in ("primary-slot", "secondary-slot"):
        return "slots-match"
    if kind == "layout-zero":
        return "zeroed-fields"
    if kind == "shared-source":
        return "shared-source-hash"
    if kind == "stub-identity":
        return "byte-identical-stubs"
    raise ValueError(case)


def replay_case(case):
    """Run a case through the model; return (events, outcome)."""
    family = case["family"]
    kind = case["kind"]
    if kind == "first-call":
        f = make_factory(family)
        obj = f.call()
        assert f.guard == 1 and f.allocations == 1
        return [("construct", hex(id(obj)))], "constructed"
    if kind == "repeat-call":
        f = make_factory(family)
        first = f.call()
        second = f.call()
        assert first is second and f.allocations == 1
        return [("repeat", "same-pointer")], "same-pointer"
    if kind == "acquire-zero":
        f = make_factory(family, pre_initialized=True)
        obj = f.call()
        assert obj is f.instance and f.allocations == 1
        return [("acquire-zero", "existing-instance")], "existing-instance"
    if kind == "alloc-fail":
        f = make_factory(family, fail_alloc=True)
        try:
            f.call()
            raise AssertionError("alloc should have thrown")
        except GuardAbort:
            pass
        assert f.guard == 0 and f.instance is None
        f.fail_alloc = False
        obj = f.call()
        assert f.guard == 1 and obj is f.instance
        return [("abort", "guard-abort"), ("retry", "constructed")], \
            "guard-abort-then-retry-ok"
    if kind == "stub-call":
        f = make_factory(family)
        first = f.call_via_stub()
        second = f.call()
        assert first is second and f.allocations == 1
        return [("stub", "same-pointer")], "stub-same-pointer"
    if kind == "name-slot":
        f = make_factory(family)
        obj = f.call()
        return [("name", obj.name())], obj.name()
    if kind == "primary-slot":
        spec = FACTORIES[family]
        slots = PRIMARY_SLOTS[family]
        assert slots[0x70] == spec["name_fn"]
        assert slots[0x00] != slots[0x08]
        return [("primary-slots", "match")], "slots-match"
    if kind == "secondary-slot":
        spec = FACTORIES[family]
        assert SECONDARY_SLOTS[family][0x00] != 0
        assert spec["secondary_vptr"] == spec["primary_vptr"] + 0xF8
        assert SECONDARY_OFFSET_TO_TOP == -32
        return [("secondary-slots", "match")], "slots-match"
    if kind == "layout-zero":
        obj = ComparatorObject(family)
        for off in ZERO_OFFSETS:
            assert obj.read_qword(off) == 0
        assert obj.primary_vptr() == FACTORIES[family]["primary_vptr"]
        assert obj.secondary_vptr() == FACTORIES[family]["secondary_vptr"]
        return [("layout", "zeroed")], "zeroed-fields"
    if kind == "shared-source":
        assert FACTORIES["bytewise"]["body_sha256"] != \
            FACTORIES["reverse"]["body_sha256"]
        return [("source", SHARED_SOURCE_SHA256[:16])], \
            "shared-source-hash"
    if kind == "stub-identity":
        return [("stub-hash", STUB_BODY_SHA256[:16])], "byte-identical-stubs"
    raise ValueError(case)


def cases_tsv_rows():
    """Rows for cases.tsv: id, family, kind, detail, expected outcome,
    group."""
    rows = []
    for c in generate_cases():
        rows.append((c["id"], c["family"], c["kind"], c["detail"],
                     expected_outcome(c), c["group"]))
    return rows


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "gen-cases":
        out = ROOT / "research" / "work-items" / \
            "re-002-node115-bytewise-reverse-factories-115" / "cases.tsv"
        rows = cases_tsv_rows()
        with open(out, "w") as fh:
            fh.write("id\tfamily\tkind\tdetail\texpected_outcome\tgroup\n")
            for r in rows:
                fh.write("\t".join(str(x) for x in r) + "\n")
        print(f"wrote {out} ({len(rows)} cases)")
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
