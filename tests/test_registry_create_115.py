"""Tests for tools/registry_create_115.py (RE-001, node #115).

Run directly (pytest is not installed on this VM):
    python3 tests/test_registry_create_115.py

Every check is target-grounded: hash vectors come from the system
libstdc++ _Hash_bytes (same seed 0xc70f6907 the binary passes),
the Status messages are the verbatim .rodata strings, and the
registry/find/translator behaviour is the pinned binary contract.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from registry_create_115 import (  # noqa: E402
    CountedPtr, FactoryEntry, FoundFactory, PatternEntry, PtrSlot,
    Registry, RegistryEntry, RegistryMap, SharedPtrSlot, StatisticsImpl,
    Status, create_by_name, delete_object, find_factory, hash_bytes,
    manager_call, submatch,
    COUNTED_STATS_VPTR, FUNCTOR_TYPEINFO, HASH_SEED,
    INVALID_ARGUMENT, MSG_COULD_NOT_LOAD, MSG_UNGUARDED, NOT_SUPPORTED,
    STATISTICS_IMPL_SIZE, STATISTICS_IMPL_VPTR, TYPE_KEY,
    TYPE_KEY_HASH,
)

CHECKS = 0
FAILED = []


def check(label, got, want):
    global CHECKS
    CHECKS += 1
    if got != want:
        FAILED.append("%s: got %r, want %r" % (label, got, want))


def check_true(label, cond):
    check(label, bool(cond), True)


# --- _Hash_bytes: ground truth from libstdc++ (seed 0xc70f6907) -----
HASH_VECTORS = [
    ("", 0x553E93901E462A6E),
    ("a", 0x454DDEE488C1ED6B),
    ("ab", 0x4C4DA6CD289C737B),
    ("abc", 0x32D82BF8ED3DBA39),
    ("abcd", 0xDE775125ACD50B28),
    ("abcde", 0x0B41619C0ED21531),
    ("abcdef", 0x22C38F395B703657),
    ("abcdefg", 0xDEEE6830A3AF82AF),
    ("abcdefgh", 0x783DB3E38DB898BB),
    ("abcdefghi", 0xB4EC9257851C8AAF),
    ("abcdefghij", 0xFA624D09F1A9F8AC),
    ("abcdefghijk", 0x32F6FAA7D12FBCE5),
    ("abcdefghijkl", 0x16D1A3AACFC6C5C8),
    ("Statistics", 0xD971F53C71278410),
    ("BasicStatistics", 0x09C2C29A91E52549),
    ("TableFactory", 0x5FC34B207B5C1B2E),
    ("x", 0xB83113FAB581D78F),
    ("yy", 0xA93A94DA8B9808C9),
    ("zzz", 0x03821B3258CCE906),
    ("123456789012345678901234567890", 0xD4565F4A9A155886),
    ("a=b", 0x63AB3E16F778F624),
    ("{a=1;b=2}", 0x39B78C1FA2329413),
]
for text, want in HASH_VECTORS:
    check("hash_bytes(%r)" % text, hash_bytes(text), want)
check("hash seed", HASH_SEED, 0xC70F6907)
check("Statistics hash", TYPE_KEY_HASH, 0xD971F53C71278410)
check("Statistics bucket13", TYPE_KEY_HASH % 13, 4)
check("Statistics bucket7", TYPE_KEY_HASH % 7, 3)

# --- Status builder 0x61cf670 ----------------------------------------
check("status ok", Status.ok(), Status(0, 0, None, 0))
check_true("status ok is_ok", Status.ok().is_ok())
s = Status.build(3, 0, "Could not load to Statistics", "Foo")
check("status code", s.code, 3)
check("status subcode", s.subcode, 0)
check("status severity", s.severity, 0)
check("status msg1+msg2", s.msg, "Could not load to Statistics: Foo")
s2 = Status.build(4, 0, "Cannot make a shared Statistics from unguarded one ")
check("status msg1 only", s2.msg,
      "Cannot make a shared Statistics from unguarded one ")
check("status msg2 empty", Status.build(4, 0, "m", ""), Status(4, 0, "m", 0))
check("status msg2 none", Status.build(4, 0, "m", None), Status(4, 0, "m", 0))

# --- PatternEntry matching (0x61f8670 / 0x61f8430 / 0x61f8280) ---------
basic = PatternEntry("BasicStatistics")
check("match exact", basic.matches("BasicStatistics"), True)
check("match case", basic.matches("basicstatistics"), False)
check("match longer", basic.matches("BasicStatistics2"), False)
check("match shorter", basic.matches("BasicStatistic"), False)
check("match empty", basic.matches(""), False)
check("match other type", basic.matches("TableFactory"), False)
check("entry name", basic.entry_name(), "BasicStatistics")
check("entry name length", basic.name_length, 15)
check("entry flag", basic.flag, 1)
check("entry offset", basic.offset, 0)

# Prefix-plus-token patterns: flag 1, offset 0, sub-patterns.
pref = PatternEntry("Foo", flag=1, offset=0,
                    sub_patterns=[(2, "Bar")])
check("prefix literal match", pref.matches("FooBar"), True)
check("prefix literal no", pref.matches("FooBaz"), False)
check("prefix literal bare", pref.matches("Foo"), True)
pint = PatternEntry("N", flag=1, offset=0, sub_patterns=[(3, "")])
check("prefix int match", pint.matches("N42"), True)
check("prefix int neg", pint.matches("N-7"), True)
check("prefix int bare", pint.matches("N"), True)
check("prefix int junk", pint.matches("N4x"), False)
pfloat = PatternEntry("F", flag=1, offset=0, sub_patterns=[(4, "")])
check("prefix float match", pfloat.matches("F1.5"), True)
check("prefix float int", pfloat.matches("F12"), True)
check("prefix float no", pfloat.matches("F."), False)
# Flag 0 blocks the whole-query path when sub-patterns exist.
noflag = PatternEntry("Foo", flag=0, offset=0, sub_patterns=[(2, "Bar")])
check("flag0 whole query", noflag.matches("Foo"), False)
check("flag0 prefix still", noflag.matches("FooBar"), True)
# Extra patterns (0x30 vector) are tried after the own name.
extra = PatternEntry("One", extra_patterns=[("Two", 3)])
check("extra pattern", extra.matches("Two"), True)
check("extra own name", extra.matches("One"), True)
check("extra neither", extra.matches("Three"), False)

# submatch unit cases.
check("submatch literal ok", submatch(2, "Bar", "FooBar", 3), 6)
check("submatch literal no", submatch(2, "Bar", "FooBaz", 3), -1)
check("submatch int", submatch(3, "", "12x", 0), 2)
check("submatch int neg", submatch(3, "", "-12", 0), 3)
check("submatch int none", submatch(3, "", "x", 0), -1)
check("submatch float", submatch(4, "", "1.5x", 0), 3)
check("submatch float dot", submatch(4, "", ".5", 0), 2)
check("submatch float none", submatch(4, "", ".", 0), -1)
check("submatch other mode", submatch(9, "ab", "xxab12", 0), 6)

# --- Manager 0x606fa50 -----------------------------------------------
dest = [None]
check("manager op0", manager_call(0, dest)[0], 0)
check("manager op0 typeinfo", dest[0], FUNCTOR_TYPEINFO)
dest = [None]
check("manager op1", manager_call(1, dest, "FUNCTOR")[0], 0)
check("manager op1 ptr", dest[0], "FUNCTOR")
check("manager op2 noop", manager_call(2, [None])[0], 0)
check("manager op3 noop", manager_call(3, [None])[0], 0)

# --- RegistryMap: linear walk (<= 20) and hash walk (> 20) ----------
def build_map(keys, bucket_count=1):
    m = RegistryMap(bucket_count)
    for k in keys:
        m.insert(k, ["factory-for-" + k])
    return m


small_keys = ["TableFactory", "MemTable", "BlockBasedTable", TYPE_KEY,
              "SkipListFactory"]
small = build_map(small_keys)
check("map small count", small.element_count, 5)
check("map small find", small.find(TYPE_KEY), ["factory-for-Statistics"])
check("map small find other", small.find("MemTable"),
      ["factory-for-MemTable"])
check("map small miss", small.find("Nope"), None)
check("map small buckets", small.bucket_count, 5)
try:
    small.insert(TYPE_KEY, ["dup"])
    check("map duplicate raises", False, True)
except KeyError:
    check("map duplicate raises", True, True)

big_keys = ["Type%02d" % i for i in range(24)] + [TYPE_KEY]
big = build_map(big_keys)
check("map big count", big.element_count, 25)
check("map big buckets", big.bucket_count, 29)
check("map big find stats", big.find(TYPE_KEY), ["factory-for-Statistics"])
for k in big_keys:
    check("map big find %s" % k, big.find(k), ["factory-for-" + k])
check("map big miss", big.find("Type99"), None)
# The Statistics node sits in the bucket the binary's hash picks.
node = big._find_node(TYPE_KEY)
check("map big node hash", node["hash"], TYPE_KEY_HASH)
check("map big node bucket",
      big.buckets[TYPE_KEY_HASH % big.bucket_count] is node, True)
# Exactly 20 elements still takes the linear walk.
edge = build_map(["K%02d" % i for i in range(19)] + [TYPE_KEY])
check("map edge count", edge.element_count, 20)
check("map edge find", edge.find(TYPE_KEY), ["factory-for-Statistics"])

# --- find_factory 0x6076620 ------------------------------------------
def registry_with(*factories, parent=None):
    reg = Registry(parent=parent)
    entry = RegistryEntry()
    for factory in factories:
        entry.map.insert(TYPE_KEY, [factory])
    reg.add_entry(entry)
    return reg


basic_factory = FactoryEntry(PatternEntry("BasicStatistics"))
reg = registry_with(basic_factory)
found = find_factory(reg, "BasicStatistics")
check_true("find found", found.found)
check("find manager", found.manager, 0x606FA50)
check("find creator is basic", found.creator is basic_factory.creator, True)
check("find functor zero", found.functor, bytes(16))
check("find no match", find_factory(reg, "Other").found, False)
check("find empty registry", find_factory(Registry(), "BasicStatistics").found,
      False)
check("find none registry", find_factory(None, "BasicStatistics").found, False)

# Later entries shadow earlier ones (vector walked last-to-first).
first = FactoryEntry(PatternEntry("BasicStatistics"))
second = FactoryEntry(PatternEntry("BasicStatistics"))
reg2 = Registry()
e1, e2 = RegistryEntry(), RegistryEntry()
e1.map.insert(TYPE_KEY, [first])
e2.map.insert(TYPE_KEY, [second])
reg2.add_entry(e1)
reg2.add_entry(e2)
check("find shadowing", find_factory(reg2, "BasicStatistics").creator
      is second.creator, True)

# Parent recursion: the child has no match, the parent does.
child = Registry(parent=registry_with(basic_factory))
check("find parent", find_factory(child, "BasicStatistics").found, True)
check("find parent miss", find_factory(child, "Other").found, False)
# A wrong type key never matches.
reg3 = Registry()
e3 = RegistryEntry()
e3.map.insert("TableFactory", [basic_factory])
reg3.add_entry(e3)
check("find wrong type", find_factory(reg3, "BasicStatistics").found, False)

# --- create_by_name 0x6076b20: success -------------------------------
slot = SharedPtrSlot()
status = create_by_name(registry_with(basic_factory), "BasicStatistics", slot)
check("create ok", status, Status.ok())
check_true("create obj", slot.obj is not None)
check("create obj vptr", slot.obj.vptr, STATISTICS_IMPL_VPTR)
check("create obj size", slot.obj.size, STATISTICS_IMPL_SIZE)
check("create obj flags", slot.obj.flags_byte, 3)
check("create control vptr", slot.control.vptr, COUNTED_STATS_VPTR)
check("create control use", slot.control.use_count, 1)
check("create control weak", slot.control.weak_count, 1)
check("create control obj", slot.control.obj is slot.obj, True)

# A second create releases the old control (dispose + destroy).
old_obj, old_control = slot.obj, slot.control
status2 = create_by_name(registry_with(basic_factory), "BasicStatistics", slot)
check("create again ok", status2, Status.ok())
check_true("create again new obj", slot.obj is not old_obj)
check("old control released", old_control.use_count, 0)
check("old control disposed", old_control.disposed, True)
check("old control destroyed", old_control.destroyed, True)
check("old obj destroyed", old_obj.destroyed, True)
check("new control fresh", slot.control.use_count, 1)

# --- create_by_name: not found ---------------------------------------
slot2 = SharedPtrSlot()
status3 = create_by_name(registry_with(basic_factory), "NoSuch", slot2)
check("create not found", status3,
      Status(3, 0, "Could not load to Statistics: NoSuch", 0))
check("create not found slot empty", slot2.obj, None)
check("create not found control", slot2.control, None)

# --- create_by_name: creator failure variants ------------------------
def failing_creator(err_msg, install=False):
    def creator(functor, name, slot, err):
        obj = None
        if install:
            obj = StatisticsImpl()
            slot.set(obj)
        if err_msg is not None:
            err[0] = err_msg
        return None
    return creator


def registry_with_creator(creator, name="BasicStatistics"):
    factory = FactoryEntry(PatternEntry(name), creator=creator)
    return registry_with(factory)


slot3 = SharedPtrSlot()
st = create_by_name(registry_with_creator(failing_creator(None)),
                    "BasicStatistics", slot3)
check("create fail no err", st,
      Status(4, 0, "Could not load to Statistics: BasicStatistics", 0))
check("create fail slot empty", slot3.obj, None)

slot4 = SharedPtrSlot()
st = create_by_name(registry_with_creator(failing_creator("boom")),
                    "BasicStatistics", slot4)
check("create fail with err", st, Status(4, 0, "boom: BasicStatistics", 0))

# Creator installs then fails: the installed object is disposed.
installed = []
def install_then_fail(functor, name, slot, err):
    obj = StatisticsImpl()
    installed.append(obj)
    slot.set(obj)
    return None

slot5 = SharedPtrSlot()
st = create_by_name(registry_with_creator(install_then_fail),
                    "BasicStatistics", slot5)
check("create fail installed status", st,
      Status(4, 0, "Could not load to Statistics: BasicStatistics", 0))
check("create fail installed destroyed", installed[0].destroyed, True)
check("create fail installed size", installed[0].deleted_size,
      STATISTICS_IMPL_SIZE)
check("create fail slot empty", slot5.obj, None)

# Creator returns an object without installing it: "unguarded", and
# the returned object is NOT deleted on this path.
leaked = []
def return_without_install(functor, name, slot, err):
    obj = StatisticsImpl()
    leaked.append(obj)
    return obj

slot6 = SharedPtrSlot()
st = create_by_name(registry_with_creator(return_without_install),
                    "BasicStatistics", slot6)
check("create unguarded", st,
      Status(4, 0,
             "Cannot make a shared Statistics from unguarded one : "
             "BasicStatistics", 0))
check("create unguarded not deleted", leaked[0].destroyed, False)
check("create unguarded slot empty", slot6.obj, None)

# --- delete_object fast path ------------------------------------------
victim = StatisticsImpl()
delete_object(victim)
check("delete fast destroyed", victim.destroyed, True)
check("delete fast size", victim.deleted_size, STATISTICS_IMPL_SIZE)
check("delete none ok", delete_object(None), None)

print("%d checks, %d failed" % (CHECKS, len(FAILED)))
for line in FAILED:
    print("FAIL: " + line)
sys.exit(1 if FAILED else 0)
