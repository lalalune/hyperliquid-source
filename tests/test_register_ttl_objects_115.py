"""Tests for tools/register_ttl_objects_115.py.

Exercises the RegisterTtlObjects behavior end-to-end: library
registration, the three factory entries in order, the
PatternEntry matcher (empty-vector exact match), creator
dispatch (MergeOperator / CompactionFilterFactory /
CompactionFilter), the std::function manager ops, the
pthread_once exactly-once semantics from both trigger entry
points, the out-slot install/replace contract, the count
results, and vector growth.  Run from the repository root:

    python3 tests/test_register_ttl_objects_115.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from register_ttl_objects_115 import (  # noqa: E402
    CREATORS, FILTER_CTOR, FILTER_FACTORY_CTOR, FILTER_FACTORY_VTABLE,
    FILTER_OPTIONS, FILTER_SIZE, FILTER_VTABLE, LIBRARY_COUNTS,
    LIBRARY_NAME, LIBRARY_TYPEINFO, LIBRARY_VTABLE,
    MERGE_OPERATOR_CTOR, MERGE_OPERATOR_OPTIONS,
    MERGE_OPERATOR_SIZE, MERGE_OPERATOR_VTABLE, PATTERN_VTABLE,
    FactoryEntry, GrowableVector, ObjectLibrary, ObjectRegistry,
    OutSlot, PatternEntry, StdFunction, TtlCompactionFilter,
    TtlCompactionFilterFactory, TtlMergeOperator, _reset_state,
    create, create_column_family_with_ttl, db_with_ttl_open,
    register_ttl_objects, sanitize_options,
    create_compaction_filter_from_factory,
)

CHECKS = [0]


def check(cond, msg):
    CHECKS[0] += 1
    assert cond, msg


# --- registration ------------------------------------------------------

reg = register_ttl_objects()
check(len(reg.libraries.items) == 1, "one library registered")
lib = reg.libraries.items[0]
check(lib.name == LIBRARY_NAME, "library name is 'TTL'")
check(lib.counts == LIBRARY_COUNTS, "library counts are 0x100000001")
check(lib.vtable == LIBRARY_VTABLE, "library cb vtable")
check(lib.typeinfo == LIBRARY_TYPEINFO, "library cb typeinfo")
check(lib.map_buckets == 1, "map starts with a single bucket")
check(lib.map_max_load_factor == 1.0, "map max load factor is 1.0")
check(lib.mutex_locked is False, "mutex released after registration")
check(sorted(lib.entries) == ["CompactionFilter",
                              "CompactionFilterFactory",
                              "MergeOperator"],
      "exactly the three map keys")
check(len(lib.find_factory("MergeOperator")) == 1,
      "one entry under MergeOperator")
check(len(lib.find_factory("CompactionFilterFactory")) == 1,
      "one entry under CompactionFilterFactory")
check(len(lib.find_factory("CompactionFilter")) == 1,
      "one entry under CompactionFilter")
check(lib.find_factory("NoSuch") == [], "absent key yields empty vector")

mo_entry = lib.find_factory("MergeOperator")[0]
cff_entry = lib.find_factory("CompactionFilterFactory")[0]
cf_entry = lib.find_factory("CompactionFilter")[0]
check(mo_entry.pattern_entry.pattern == "TtlMergeOperator",
      "MO pattern is TtlMergeOperator")
check(cff_entry.pattern_entry.pattern == "TtlCompactionFilterFactory",
      "CFF pattern is TtlCompactionFilterFactory")
check(cf_entry.pattern_entry.pattern == "TtlCompactionFilter",
      "CF pattern is TtlCompactionFilter")
for entry in (mo_entry, cff_entry, cf_entry):
    check(entry.pattern_entry.elements == [],
          "TTL entries have no sub-pattern elements")
    check(entry.pattern_entry.flag == 1, "flag byte is 1")
    check(entry.pattern_entry.sub_patterns == [],
          "no sub-patterns")
    check(entry.pattern_entry.pattern_length ==
          len(entry.pattern_entry.pattern),
          "pattern-length copy matches")
    check(entry.functor == 0, "functor storage is zero")
    check(entry.pattern_entry.vtable == PATTERN_VTABLE,
          "PatternEntry vtable")
check(mo_entry.vtable == 0x64D86A0, "MO factory vtable")
check(cff_entry.vtable == 0x64D9D38, "CFF factory vtable")
check(cf_entry.vtable == 0x64D7DA0, "CF factory vtable")
check(mo_entry.manager == 0x62009A0, "MO manager")
check(cff_entry.manager == 0x62009D0, "CFF manager")
check(cf_entry.manager == 0x6200A00, "CF manager")
check(mo_entry.invoker == 0x62056B0, "MO invoker")
check(cff_entry.invoker == 0x6205C60, "CFF invoker")
check(cf_entry.invoker == 0x6202CA0, "CF invoker")
check(mo_entry.creator is CREATORS["MergeOperator"], "MO creator row")
check(cff_entry.creator is CREATORS["CompactionFilterFactory"],
      "CFF creator row")
check(cf_entry.creator is CREATORS["CompactionFilter"], "CF creator row")

# FactoryEntry layout: +0x08 PatternEntry*, +0x20 manager,
# +0x28 invoker; D2 destroys the function (manager op 3) and
# deletes the PatternEntry; D0 is D2 plus the free.
victim = FactoryEntry("MergeOperator", "TtlMergeOperator",
                      CREATORS["MergeOperator"])
victim.destroy_d2()
check(victim.destroyed, "D2 marks the entry destroyed")
check(victim.pattern_entry is None, "D2 deletes the PatternEntry")
victim2 = FactoryEntry("CompactionFilter", "TtlCompactionFilter",
                       CREATORS["CompactionFilter"])
victim2.destroy_d0()
check(victim2.destroyed, "D0 destroys the entry too")

# --- PatternEntry matcher (exact-match only) ---------------------------

check(mo_entry.matches("TtlMergeOperator"), "exact pattern matches")
check(not mo_entry.matches("TtlMergeOperatorX"),
      "longer query does not match (exact only)")
check(not mo_entry.matches("TtlMergeOperato"),
      "shorter query does not match")
check(not mo_entry.matches("ttlmergeoperator"),
      "matching is case-sensitive")
check(cff_entry.matches("TtlCompactionFilterFactory"),
      "CFF exact pattern matches")
check(not cff_entry.matches("TtlCompactionFilterFactor"),
      "CFF shorter query does not match")
check(cf_entry.matches("TtlCompactionFilter"), "CF exact matches")
check(not cf_entry.matches("TtlCompactionFilter "),
      "CF trailing space does not match")

# The matcher still implements the element protocol (PR #3983):
# with elements, a prefix plus element sequence decides.
pe = PatternEntry("TtlMergeOperator")
pe.elements = [("://test", 2)]
check(not pe.matches("TtlMergeOperator"),
      "mode-2 element requires the tail to reach the end")
check(pe.matches("TtlMergeOperator://test"),
      "mode-2 element matches the full tail")
check(not pe.matches("TtlMergeOperator://tes"),
      "mode-2 element rejects a partial tail")

# --- creator dispatch ----------------------------------------------------

slot = OutSlot()
obj = create(reg, "MergeOperator", "TtlMergeOperator", slot)
check(isinstance(obj, TtlMergeOperator), "create MO yields the operator")
check(slot.ptr is obj, "MO creator installs into the out slot")
check(obj.wrapped is None, "MO creator builds an empty wrapped operator")
check(obj.wrapped_cb is None, "MO wrapped control block is null")
check(obj.clock is None, "MO creator builds a null clock")
check(obj.vtable == MERGE_OPERATOR_VTABLE, "MO vtable")
check(obj.size == MERGE_OPERATOR_SIZE, "MO size is 0x38")
check(obj.options == [("TtlMergeOptions", 0x6509480,
                       "wrapped_shared_ptr")],
      "MO registers TtlMergeOptions")
check(obj.options_vector == [], "MO +0x08 vector starts empty")

slot2 = OutSlot()
obj2 = create(reg, "CompactionFilterFactory",
              "TtlCompactionFilterFactory", slot2)
check(isinstance(obj2, TtlCompactionFilterFactory),
      "create CFF yields the factory")
check(slot2.ptr is obj2, "CFF creator installs into the out slot")
check(obj2.ttl == 0, "CFF creator builds ttl 0")
check(obj2.clock is None, "CFF creator builds a null clock")
check(obj2.wrapped is None, "CFF creator builds an empty wrapped factory")
check(obj2.vtable == FILTER_FACTORY_VTABLE, "CFF vtable")
check(obj2.size == 0x40, "CFF size is 0x40")
check(obj2.options == [("UserOptions", 0x6509400,
                        "wrapped_shared_ptr"),
                       ("TTL", 0x6509440, "ttl")],
      "CFF registers UserOptions and TTL")

obj3 = create(reg, "CompactionFilter", "TtlCompactionFilter")
check(isinstance(obj3, TtlCompactionFilter),
      "create CF yields the filter")
check(obj3.ttl == 0, "CF creator builds ttl 0")
check(obj3.clock is None, "CF creator builds a null clock")
check(obj3.filter is None, "CF creator builds a null filter")
check(obj3.owned is None, "CF creator builds an empty owned pointer")
check(obj3.vtable == FILTER_VTABLE, "CF vtable")
check(obj3.size == FILTER_SIZE, "CF size is 0x40")
check(obj3.options == [("TTL", 0x6509440, "ttl"),
                       ("UserFilter", 0x65093C0, "filter")],
      "CF registers TTL and UserFilter")

check(create(reg, "MergeOperator", "nope", OutSlot()) is None,
      "create returns None when the pattern does not match")
check(create(reg, "NoSuch", "TtlMergeOperator", OutSlot()) is None,
      "create on an absent name returns None")
check(create(ObjectRegistry(), "MergeOperator", "TtlMergeOperator",
             OutSlot()) is None,
      "create on an empty registry returns None")

# Out-slot install replaces and D1-destroys the previous object.
old = TtlMergeOperator()
slot3 = OutSlot()
slot3.install(old)
check(slot3.ptr is old, "slot holds the first object")
new = TtlMergeOperator()
slot3.install(new)
check(slot3.ptr is new, "slot holds the replacement")
check(old.destroyed_via_d1, "previous object destroyed via D1")
check(slot3.disposed == [old], "disposed list records the old object")

# --- std::function manager protocol --------------------------------------

fn = StdFunction(0x6208290, 0x6201000, 0x6200A30,
                 "register-manager-typeinfo")
to = [None]
check(fn.manager_call(to, [0x6208290], 0) is True,
      "manager op 0 returns true")
check(to[0] == "register-manager-typeinfo",
      "manager op 0 stores the typeinfo")
to = [None]
check(fn.manager_call(to, [0x6208290], 1) is True,
      "manager op 1 returns true")
check(to[0] == 0x6208290, "manager op 1 stores the functor")
check(fn.manager_call([None], [None], 2) is False,
      "manager op 2 returns false")
check(fn.manager_call([None], [None], 3) is False,
      "manager op 3 returns false")
clone = fn.clone()
check(clone.functor == fn.functor and clone.manager == fn.manager
      and clone.invoker == fn.invoker,
      "clone copies the (manager, invoker) pair bitwise")
try:
    fn.manager_call([None], [None], 9)
    check(False, "unknown manager op must raise")
except ValueError:
    check(True, "unknown manager op raises")

# --- pthread_once exactly-once, both trigger paths -----------------------

_reset_state()
reg_a = db_with_ttl_open()
check(len(reg_a.libraries.items) == 1,
      "Open registers the TTL library")
check(reg_a.libraries.items[0].name == "TTL",
      "Open registers the TTL library by name")
reg_b = create_column_family_with_ttl()
check(reg_b is reg_a, "CreateColumnFamily reuses the same registry")
check(len(reg_b.libraries.items) == 1,
      "second trigger does not register a second library")
reg_c = db_with_ttl_open()
check(len(reg_c.libraries.items) == 1,
      "third trigger still leaves one library")

# --- count ---------------------------------------------------------------

total, element_count = lib.count()
check(total == 3, "count returns 3 total entries")
check(element_count == 3, "count returns element count 3")
check(lib.mutex_locked is False, "count releases the mutex")

# --- consumers -----------------------------------------------------------

merge, filt, factory = sanitize_options(3600, clock="clock",
                                        wrapped_merge="wrapped-mo",
                                        wrapped_factory="wrapped-cff",
                                        wrapped_filter="wrapped-cf")
check(isinstance(merge, TtlMergeOperator), "SanitizeOptions builds MO")
check(merge.wrapped == "wrapped-mo", "SanitizeOptions passes the wrapped MO")
check(merge.clock == "clock", "SanitizeOptions passes the clock to MO")
check(isinstance(filt, TtlCompactionFilter),
      "SanitizeOptions builds the filter")
check(filt.ttl == 3600, "SanitizeOptions passes ttl to the filter")
check(filt.filter == "wrapped-cf",
      "SanitizeOptions passes the wrapped filter")
check(isinstance(factory, TtlCompactionFilterFactory),
      "SanitizeOptions builds the factory")
check(factory.ttl == 3600, "SanitizeOptions passes ttl to the factory")
check(factory.wrapped == "wrapped-cff",
      "SanitizeOptions passes the wrapped factory")

made = create_compaction_filter_from_factory(factory, 60)
check(isinstance(made, TtlCompactionFilter),
      "CreateCompactionFilter builds a filter")
check(made.ttl == 60, "CreateCompactionFilter passes ttl")

# --- vector growth ---------------------------------------------------------

vec = GrowableVector()
for i in range(5):
    vec.append(i)
check(len(vec) == 5, "five items appended")
check(vec.capacity == 8, "vector doubled to 8")
check(vec.items == [0, 1, 2, 3, 4], "vector order preserved")

reg2 = ObjectRegistry()
for i in range(3):
    reg2.append_library(ObjectLibrary("lib%d" % i))
check(len(reg2.libraries.items) == 3, "three libraries appended")
check(reg2.libraries.capacity == 4, "libraries vector doubled to 4")

# --- pinned addresses ------------------------------------------------------

check(MERGE_OPERATOR_CTOR == 0x6205560, "MO ctor address")
check(FILTER_FACTORY_CTOR == 0x6205790, "CFF ctor address")
check(FILTER_CTOR == 0x6202A10, "CF ctor address")
check(MERGE_OPERATOR_OPTIONS == ("TtlMergeOptions", 0x6509480),
      "MO option global")
check(FILTER_OPTIONS == (("TTL", 0x6509440),
                         ("UserFilter", 0x65093C0)),
      "CF option globals")

print("%d checks passed" % CHECKS[0])
