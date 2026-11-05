"""Tests for the node #115 memtable-factory record holders.

Run directly (pytest is not installed on this VM):
    python3 tests/test_skiplist_holder_115.py

Every expectation is grounded in the evidence packet
research/work-items/RE-001-skiplist-holder-115/: the holder ctor
0x6064440, the HashLinkListRepFactory ctor 0x605F150, the base
init 0x60B3C30, the replacement gate in 0x5D946B0, the ":" setters
0x61935B0/0x6193390, and the registry builder 0x6195290.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from skiplist_holder_115 import (  # noqa: E402
    GATE_LENGTH,
    GATE_NAME_A,
    GATE_NAME_B,
    HASH_DEFAULT_VALUE,
    HASH_FACTORY_RECORD_KEY,
    HASH_FACTORY_VTABLE,
    HASH_HOLDER_SIZE,
    HASH_RECORD_B,
    INPLACE_CONTROL_SIZE,
    INPLACE_CONTROL_VTABLE,
    REFCOUNT_ONE_ONE,
    REGISTRY,
    SEPARATE_CONTROL_SIZE,
    SEPARATE_CONTROL_TYPEINFO,
    SEPARATE_CONTROL_VTABLE,
    SKIPLIST_FACTORY_NAME,
    SKIPLIST_FACTORY_SHORT_ID,
    SKIPLIST_FACTORY_VTABLE,
    SKIPLIST_HOLDER_SIZE,
    SKIPLIST_RECORD_B,
    SKIPLIST_RECORD_KEY,
    Holder,
    Record,
    SharedPtrSlot,
    accessor,
    build_hashlink_holder,
    build_skiplist_holder,
    hashlink_record,
    parse_decimal,
    replacement_gate_passes,
    setter_hash,
    setter_skip,
    skiplist_record,
    split_colon,
)

CHECKS = []


def check(name, cond):
    CHECKS.append((name, bool(cond)))
    if not cond:
        print("FAIL: %s" % name)


def expect_raises(name, fn, *args):
    try:
        fn(*args)
    except ValueError:
        CHECKS.append((name, True))
    else:
        CHECKS.append((name, False))
        print("FAIL: %s (no ValueError)" % name)


# --- Record keys and fields (rebuilt from the raw constants) ----------------
check("skiplist key is 22 chars", len(SKIPLIST_RECORD_KEY) == 22)
check("skiplist key value", SKIPLIST_RECORD_KEY == "SkipListFactoryOptions")
check("skiplist key prefix 16", SKIPLIST_RECORD_KEY[:16] == "SkipListFactoryO")
check("skiplist key suffix 8", SKIPLIST_RECORD_KEY[14:] == "yOptions")
check("hash key is 29 chars", len(HASH_FACTORY_RECORD_KEY) == 29)
check("hash key value",
      HASH_FACTORY_RECORD_KEY == "HashLinkListRepFactoryOptions")
check("hash key prefix 16", HASH_FACTORY_RECORD_KEY[:16] == "HashLinkListRepF")
check("hash key suffix 16", HASH_FACTORY_RECORD_KEY[13:] == "epFactoryOptions")

rec = skiplist_record(0)
check("skiplist record a=0", rec.a == 0)
check("skiplist record b", rec.b == SKIPLIST_RECORD_B == 0x6505C40)
check("skiplist record size", Record.SIZE == 0x30)
rec2 = skiplist_record(50000)
check("skiplist record carries a", rec2.a == 50000)
check("skiplist record b stable", rec2.b == SKIPLIST_RECORD_B)
rec3 = hashlink_record(4096)
check("hash record key", rec3.key == HASH_FACTORY_RECORD_KEY)
check("hash record a", rec3.a == 4096)
check("hash record b", rec3.b == HASH_RECORD_B == 0x6505B80)
check("records differ by key", skiplist_record(0) != hashlink_record(0))

# --- Holder construction ----------------------------------------------------
h = build_skiplist_holder(0)
check("skiplist holder vtable", h.vtable == SKIPLIST_FACTORY_VTABLE == 0x64D27B0)
check("skiplist holder size", h.size == SKIPLIST_HOLDER_SIZE == 0x28)
check("skiplist holder one record", len(h.records) == 1)
check("skiplist holder +0x20 is a", h.field_0x20 == 0)
h2 = build_skiplist_holder(1234)
check("skiplist holder +0x20 carries value", h2.field_0x20 == 1234)

hh = build_hashlink_holder(50000)
check("hash holder vtable", hh.vtable == HASH_FACTORY_VTABLE == 0x64D2230)
check("hash holder size", hh.size == HASH_HOLDER_SIZE == 0x40)
check("hash holder one record", len(hh.records) == 1)
check("hash holder +0x20 is value", hh.field_0x20 == 50000)
check("hash holder +0x28 is r8", hh.field_0x28 == 0x100)
check("hash holder +0x30 is rsi", hh.field_0x30 == 0)
check("hash holder +0x38 is rdx", hh.field_0x38 == 0x1000)
check("hash holder +0x3c is rcx", hh.field_0x3c == 1)
hh2 = build_hashlink_holder(7, rsi=0, rdx=0x1000, rcx=1, r8=0x100)
check("hash holder +0x20 carries parsed", hh2.field_0x20 == 7)

# --- Shared_ptr installation ------------------------------------------------
slot = SharedPtrSlot()
check("slot starts empty", slot.object is None and slot.control is None)
check("release on empty is False", slot.release_old() is False)
slot.install_separate(h)
check("separate install object", slot.object is h)
check("separate control vtable", slot.control[0] == SEPARATE_CONTROL_VTABLE == 0x64D3780)
check("separate control typeinfo",
      SEPARATE_CONTROL_TYPEINFO == "St15_Sp_counted_ptrIPN7rocksdb15SkipListFactoryE"
      "LN9__gnu_cxx12_Lock_policyE2EE")
check("separate control size", slot.control[1] == SEPARATE_CONTROL_SIZE == 0x18)
check("separate control counts", slot.control[2] == REFCOUNT_ONE_ONE)
check("separate control holds object", slot.control[3] is h)
check("refcount qword is {1,1}", REFCOUNT_ONE_ONE == 0x100000001)
check("release on installed is True", slot.release_old() is True)
check("release clears control", slot.control is None)
slot.install_inplace(h2)
check("inplace control vtable", slot.control[0] == INPLACE_CONTROL_VTABLE)
check("inplace control size", slot.control[1] == INPLACE_CONTROL_SIZE == 0x38)
check("inplace control counts", slot.control[2] == REFCOUNT_ONE_ONE)
check("inplace control holds object", slot.control[3] is h2)
check("inplace object pointer", slot.object is h2)

# --- Replacement gate -------------------------------------------------------
check("gate length is 22", GATE_LENGTH == 0x16)
check("gate name A is 22 chars", len(GATE_NAME_A) == 22)
check("gate name A value", GATE_NAME_A == "HashSkipListRepFactory")
check("gate name B is 22 chars", len(GATE_NAME_B) == 22)
check("gate name B value", GATE_NAME_B == "HashLinkListRepFactory")
check("gate passes HashSkipListRepFactory",
      replacement_gate_passes("HashSkipListRepFactory") is True)
check("gate passes HashLinkListRepFactory",
      replacement_gate_passes("HashLinkListRepFactory") is True)
check("gate rejects SkipListFactory",
      replacement_gate_passes(SKIPLIST_FACTORY_NAME) is False)
check("gate rejects 22-char lookalike",
      replacement_gate_passes("HashSkipListRepFactorx") is False)
check("gate rejects 21-char prefix",
      replacement_gate_passes("HashSkipListRepFactor") is False)
check("gate rejects 23-char name",
      replacement_gate_passes("HashSkipListRepFactoryX") is False)
check("gate rejects None", replacement_gate_passes(None) is False)
check("gate rejects empty", replacement_gate_passes("") is False)
# Both gate literals are 22 chars; either hash factory name passes.
check("gate literals both 22 chars",
      len(GATE_NAME_A) == 22 and len(GATE_NAME_B) == 22)

# --- Decimal parse ----------------------------------------------------------
check("parse plain", parse_decimal("50000") == 50000)
check("parse zero", parse_decimal("0") == 0)
check("parse K suffix", parse_decimal("1K") == 1024)
check("parse M suffix", parse_decimal("2M") == 2 * 1024 * 1024)
check("parse G suffix", parse_decimal("1G") == 1024 ** 3)
check("parse T suffix", parse_decimal("1T") == 1024 ** 4)
expect_raises("parse empty raises", parse_decimal, "")
expect_raises("parse non-digit raises", parse_decimal, "abc")
expect_raises("parse bad suffix raises", parse_decimal, "12X")
expect_raises("parse trailing raises", parse_decimal, "12K3")
expect_raises("parse overflow raises", parse_decimal, "99999999999999999999")

# --- ":" split --------------------------------------------------------------
check("split no colon", split_colon("skip_list") == (False, "skip_list", None))
check("split with colon", split_colon("skip_list:50000") == (True, "skip_list", "50000"))
check("split empty tail", split_colon("a:") == (True, "a", ""))
check("split first colon only", split_colon("a:b:c") == (True, "a", "b:c"))

# --- Setters ----------------------------------------------------------------
slot1 = [None]
new1 = setter_skip("skip_list:4096", slot1)
check("setter_skip installs holder", slot1[0] is new1)
check("setter_skip holder is skiplist", new1.vtable == SKIPLIST_FACTORY_VTABLE)
check("setter_skip parsed value", new1.field_0x20 == 4096)
check("setter_skip record key", new1.records[0].key == SKIPLIST_RECORD_KEY)
slot2 = [build_skiplist_holder(9)]
old2 = slot2[0]
new2 = setter_skip("skip_list", slot2)
check("setter_skip default a=0", new2.field_0x20 == 0)
check("setter_skip replaces slot", slot2[0] is new2)
check("setter_skip destroys old via slot 1",
      getattr(old2, "destroyed_via_slot1", False) is True)
slot3 = [None]
new3 = setter_hash("hash_linkedlist:2048", slot3)
check("setter_hash installs holder", slot3[0] is new3)
check("setter_hash holder is hashlink", new3.vtable == HASH_FACTORY_VTABLE)
check("setter_hash parsed value", new3.field_0x20 == 2048)
check("setter_hash fixed rdx", new3.field_0x38 == 0x1000)
check("setter_hash fixed rcx", new3.field_0x3c == 1)
check("setter_hash fixed r8", new3.field_0x28 == 0x100)
slot4 = [build_hashlink_holder(1)]
old4 = slot4[0]
new4 = setter_hash("hash_linkedlist", slot4)
check("setter_hash default 50000", new4.field_0x20 == HASH_DEFAULT_VALUE == 50000)
check("setter_hash destroys old via slot 1",
      getattr(old4, "destroyed_via_slot1", False) is True)
expect_raises("setter_skip bad number raises", setter_skip,
              "skip_list:xx", [None])
expect_raises("setter_hash bad number raises", setter_hash,
              "hash_linkedlist:xx", [None])

# --- Registry ----------------------------------------------------------------
check("registry has skip_list", "skip_list" in REGISTRY)
check("registry has hash_linkedlist", "hash_linkedlist" in REGISTRY)
check("skip_list setter", REGISTRY["skip_list"]["setter"] == 0x61935B0)
check("skip_list long name", REGISTRY["skip_list"]["long_name"] == "SkipListFactory")
check("skip_list accessor", REGISTRY["skip_list"]["accessor"] == 0x6192860)
check("skip_list accessor index0", REGISTRY["skip_list"]["accessor_index0"] == 0x64D65D8)
check("hash setter", REGISTRY["hash_linkedlist"]["setter"] == 0x6193390)
check("hash long name", REGISTRY["hash_linkedlist"]["long_name"] == "HashLinkListRepFactory")
check("hash accessor", REGISTRY["hash_linkedlist"]["accessor"] == 0x6192890)
check("hash accessor index0", REGISTRY["hash_linkedlist"]["accessor_index0"] == 0x64D65E8)
check("factory short id", SKIPLIST_FACTORY_SHORT_ID == "skip_list")
check("accessor skip index0", accessor(True, 0) == 0x64D65D8)
check("accessor hash index0", accessor(False, 0) == 0x64D65E8)
check("accessor index1 stores value", accessor(True, 1, value=0x1234) == 0x1234)
check("accessor other index stores nothing", accessor(True, 2) is None)
check("accessor other index stores nothing (hash)", accessor(False, 7) is None)

# --- Vtable slot tables -----------------------------------------------------
from skiplist_holder_115 import (  # noqa: E402
    HASH_FACTORY_NAME,
    HASH_FACTORY_TYPEINFO,
    INPLACE_CONTROL_SLOT5_RAW_ZERO,
    INPLACE_CONTROL_VTABLE,
    SEPARATE_CONTROL_VTABLE,
    TYPEINFO_NAMES,
    TYPEINFO_NAME_POINTERS,
    TYPEINFO_POINTERS,
    VTABLE_SLOTS,
)
check("vtable count", len(VTABLE_SLOTS) == 4)
check("skiplist vtable slot count", len(VTABLE_SLOTS[0x64D27B0]) == 23)
check("hash vtable slot count", len(VTABLE_SLOTS[0x64D2230]) == 23)
check("separate control slot count", len(VTABLE_SLOTS[0x64D3780]) == 5)
check("inplace control RELATIVE slot count",
      len(VTABLE_SLOTS[0x64C9C00]) == 5)
check("inplace control slot 5 raw zero", INPLACE_CONTROL_SLOT5_RAW_ZERO is True)
check("total RELATIVE vtable slots",
      sum(len(s) for s in VTABLE_SLOTS.values()) == 56)
check("skiplist slot 14 is Name", VTABLE_SLOTS[0x64D27B0][0x70] == 0x6062F70)
check("hash slot 14 is Name", VTABLE_SLOTS[0x64D2230][0x70] == 0x605EA40)
check("skiplist slot 18 is short id", VTABLE_SLOTS[0x64D27B0][0x90] == 0x6062F80)
check("skiplist slot 19 is transient consumer",
      VTABLE_SLOTS[0x64D27B0][0x98] == 0x6063640)
check("skiplist slot 1 is destroy", VTABLE_SLOTS[0x64D27B0][0x08] == 0x6063430)
check("hash slot 1 is destroy", VTABLE_SLOTS[0x64D2230][0x08] == 0x605EF70)
check("shared slots 2..13 identical",
      all(VTABLE_SLOTS[0x64D27B0][off] == VTABLE_SLOTS[0x64D2230][off]
          for off in (0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48,
                      0x50, 0x58, 0x60, 0x68)))
check("shared slot 16 identical",
      VTABLE_SLOTS[0x64D27B0][0x80] == VTABLE_SLOTS[0x64D2230][0x80] == 0x5D2E770)
check("shared slot 17 identical",
      VTABLE_SLOTS[0x64D27B0][0x88] == VTABLE_SLOTS[0x64D2230][0x88] == 0x5D2CA00)
check("shared slot 20 identical",
      VTABLE_SLOTS[0x64D27B0][0xA0] == VTABLE_SLOTS[0x64D2230][0xA0] == 0x5F04D90)
check("typeinfo pointers", TYPEINFO_POINTERS == {
    0x64D27B0: 0x64D25A8, 0x64D2230: 0x64D2068,
    0x64D3780: 0x64D3728, 0x64C9C00: 0x64C99C0})
check("typeinfo name pointers", TYPEINFO_NAME_POINTERS == {
    0x64D25A8: 0x975160, 0x64D2068: 0x975020,
    0x64D3728: 0x978540, 0x64C99C0: 0x96D980})
check("skiplist typeinfo name",
      TYPEINFO_NAMES[0x975160] == "N7rocksdb15SkipListFactoryE")
check("hash typeinfo name has leading star",
      TYPEINFO_NAMES[0x975020] ==
      "*N7rocksdb12_GLOBAL__N_122HashLinkListRepFactoryE")
check("hash typeinfo name matches model constant",
      TYPEINFO_NAMES[0x975020] == HASH_FACTORY_TYPEINFO)
check("separate control typeinfo name",
      TYPEINFO_NAMES[0x978540] == SEPARATE_CONTROL_TYPEINFO)
check("inplace control typeinfo name",
      TYPEINFO_NAMES[0x96D980] ==
      "St23_Sp_counted_ptr_inplaceIN7rocksdb15SkipListFactoryE"
      "SaIvELN9__gnu_cxx12_Lock_policyE2EE")
check("inplace control vtable", INPLACE_CONTROL_VTABLE == 0x64C9C00)
check("separate control vtable", SEPARATE_CONTROL_VTABLE == 0x64D3780)

# --- Digest ------------------------------------------------------------------
from skiplist_holder_115 import NODE115_DIGEST  # noqa: E402
check("digest bound to node #115",
      NODE115_DIGEST == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")


def main():
    failed = [name for name, ok in CHECKS if not ok]
    print("ran %d checks, %d failed" % (len(CHECKS), len(failed)))
    if failed:
        print("FAILED: %s" % ", ".join(failed))
        return 1
    print("all %d checks passed" % len(CHECKS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
