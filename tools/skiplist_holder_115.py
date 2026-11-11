"""Model of node #115's memtable-factory record holders.

Ground: research/work-items/RE-001-skiplist-holder-115/ (PR #3263
follow-up). All addresses are node #115 virtual addresses; the
target digest is a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.

The pinned behaviour, end to end:
  * The 0x28-byte `rocksdb::SkipListFactory` holder (ctor 0x6064440)
    carries a record vector at +0x08 and registers exactly one
    record {"SkipListFactoryOptions", a, 0x6505c40}; `a` is the
    ctor's second argument.
  * The 0x40-byte `rocksdb::(anonymous namespace)::HashLinkListRepFactory`
    holder (ctor 0x605F150) registers one record
    {"HashLinkListRepFactoryOptions", a, 0x6505b80}.
  * The options object holds the SkipListFactory as an inline
    shared_ptr at +0x128 (object) / +0x130 (control): a separate
    0x18-byte `_Sp_counted_ptr` control (base init 0x60B3C30) or a
    0x38-byte `_Sp_counted_ptr_inplace<SkipListFactory>` control
    (replacement in 0x5D946B0). Both start {use=1, weak=1}.
  * The replacement rebuilds the holder only when the current
    factory's Name() (vtable slot 14) is exactly 22 chars and
    equals "HashSkipListRepFactory" or "HashLinkListRepFactory";
    either hash factory is normalised to a plain SkipListFactory.
  * The ":" setters (0x61935B0 skip_list, 0x6193390
    hash_linkedlist) parse the substring after ":" as a decimal
    (K/M/G/T suffixes, via 0x61D1540) and install the fresh
    factory at *rbp+0x00, destroying the old one through its
    vtable slot 1. With no ":" the skip_list setter builds the
    default holder (a=0); the hash setter builds with 50000.
"""

# --- Constants pinned from the binary -------------------------------------

NODE115_DIGEST = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)

SKIPLIST_FACTORY_VTABLE = 0x64D27B0
SKIPLIST_FACTORY_TYPEINFO = "N7rocksdb15SkipListFactoryE"
SKIPLIST_FACTORY_NAME = "SkipListFactory"          # vtable slot 14 (0x6062F70)
SKIPLIST_FACTORY_SHORT_ID = "skip_list"            # vtable slot 18 (0x6062F80)
SKIPLIST_RECORD_KEY = "SkipListFactoryOptions"     # 22 chars
SKIPLIST_RECORD_B = 0x6505C40  # BSS address; no file bytes, no RELATIVE record
SKIPLIST_HOLDER_SIZE = 0x28

HASH_FACTORY_VTABLE = 0x64D2230
HASH_FACTORY_TYPEINFO = "*N7rocksdb12_GLOBAL__N_122HashLinkListRepFactoryE"
HASH_FACTORY_NAME = "HashLinkListRepFactory"  # vtable slot 14 (0x605EA40)
HASH_FACTORY_RECORD_KEY = "HashLinkListRepFactoryOptions"  # 29 chars
HASH_RECORD_B = 0x6505B80  # BSS address; no file bytes, no RELATIVE record
HASH_HOLDER_SIZE = 0x40

# Shared_ptr control blocks for the options +0x128/+0x130 pair.
SEPARATE_CONTROL_VTABLE = 0x64D3780  # _Sp_counted_ptr<SkipListFactory*>
SEPARATE_CONTROL_TYPEINFO = (
    "St15_Sp_counted_ptrIPN7rocksdb15SkipListFactoryE"
    "LN9__gnu_cxx12_Lock_policyE2EE"
)
SEPARATE_CONTROL_SIZE = 0x18
INPLACE_CONTROL_VTABLE = 0x64C9C00  # _Sp_counted_ptr_inplace<SkipListFactory>
INPLACE_CONTROL_SIZE = 0x38
REFCOUNT_ONE_ONE = 0x100000001  # {use=1, weak=1} as one qword

# Replacement gate (0x5D946B0): the two compared names.
GATE_NAME_A = "HashSkipListRepFactory"   # 22 chars
GATE_NAME_B = "HashLinkListRepFactory"   # 22 chars
GATE_LENGTH = 0x16  # 22

# ":" setter defaults.
SKIP_DEFAULT_A = 0
HASH_DEFAULT_VALUE = 50000        # 0xC350
HASH_FIXED_ARGS = (0, 0x1000, 1, 0x100)  # (rsi, rdx, rcx, r8) to 0x605F150

# Registry entries built by 0x6195290.
REGISTRY = {
    "skip_list": {
        "long_name": "SkipListFactory",
        "setter": 0x61935B0,
        "accessor": 0x6192860,
        "accessor_index0": 0x64D65D8,
    },
    "hash_linkedlist": {
        "long_name": "HashLinkListRepFactory",
        "setter": 0x6193390,
        "accessor": 0x6192890,
        "accessor_index0": 0x64D65E8,
    },
}

# Vtable slot tables (offsets are from the vtable address; values
# are the RELATIVE addends in relocations.txt). The inplace
# control's slot 5 is a raw 0 with no RELATIVE record, so it is
# recorded separately and is not in the table below.
VTABLE_SLOTS = {
    0x64D27B0: {  # rocksdb::SkipListFactory (23 slots)
        0x00: 0x60633A0, 0x08: 0x6063430, 0x10: 0x609D760,
        0x18: 0x609DC40, 0x20: 0x5D32560, 0x28: 0x6095E70,
        0x30: 0x6096790, 0x38: 0x5D2E090, 0x40: 0x60956F0,
        0x48: 0x609D0E0, 0x50: 0x60986B0, 0x58: 0x6095710,
        0x60: 0x609DE80, 0x68: 0x609D980, 0x70: 0x6062F70,  # slot 14: Name
        0x78: 0x6063970, 0x80: 0x5D2E770, 0x88: 0x5D2CA00,
        0x90: 0x6062F80,  # slot 18: short id "skip_list"
        0x98: 0x6063640,  # slot 19: transient consumer
        0xA0: 0x5F04D90, 0xA8: 0x6062F90, 0xB0: 0x6062FA0,
    },
    0x64D2230: {  # HashLinkListRepFactory (23 slots)
        0x00: 0x605EEE0, 0x08: 0x605EF70, 0x10: 0x609D760,
        0x18: 0x609DC40, 0x20: 0x5D32560, 0x28: 0x6095E70,
        0x30: 0x6096790, 0x38: 0x5D2E090, 0x40: 0x60956F0,
        0x48: 0x609D0E0, 0x50: 0x60986B0, 0x58: 0x6095710,
        0x60: 0x609DE80, 0x68: 0x609D980, 0x70: 0x605EA40,  # slot 14: Name
        0x78: 0x5D32A30, 0x80: 0x5D2E770, 0x88: 0x5D2CA00,
        0x90: 0x605EA50, 0x98: 0x605EB40, 0xA0: 0x5F04D90,
        0xA8: 0x605E920, 0xB0: 0x605E930,
    },
    0x64D3780: {  # _Sp_counted_ptr<SkipListFactory*> (5 slots)
        0x00: 0x60B1DC0, 0x08: 0x60B1E40, 0x10: 0x60B1E10,
        0x18: 0x60B1E50, 0x20: 0x60B1E30,
    },
    0x64C9C00: {  # _Sp_counted_ptr_inplace<SkipListFactory> (5 RELATIVE)
        0x00: 0x5D89720, 0x08: 0x5D897C0, 0x10: 0x5D89750,
        0x18: 0x5D89AC0, 0x20: 0x5D89E30,
    },
}
INPLACE_CONTROL_SLOT5_RAW_ZERO = True  # slot 5 at 0x64C9C28: raw 0

# Typeinfo pointers: vtable-0x08 -> typeinfo, typeinfo+0x08 -> name.
TYPEINFO_POINTERS = {
    0x64D27B0: 0x64D25A8,
    0x64D2230: 0x64D2068,
    0x64D3780: 0x64D3728,
    0x64C9C00: 0x64C99C0,
}
TYPEINFO_NAME_POINTERS = {
    0x64D25A8: 0x975160,
    0x64D2068: 0x975020,
    0x64D3728: 0x978540,
    0x64C99C0: 0x96D980,
}
# Typeinfo name strings at those addresses (as stored in the binary;
# the hash factory's name carries a leading '*' byte).
TYPEINFO_NAMES = {
    0x975160: "N7rocksdb15SkipListFactoryE",
    0x975020: "*N7rocksdb12_GLOBAL__N_122HashLinkListRepFactoryE",
    0x978540: "St15_Sp_counted_ptrIPN7rocksdb15SkipListFactoryE"
              "LN9__gnu_cxx12_Lock_policyE2EE",
    0x96D980: "St23_Sp_counted_ptr_inplaceIN7rocksdb15SkipListFactoryE"
              "SaIvELN9__gnu_cxx12_Lock_policyE2EE",
}

# Decimal suffix shifts of the 0x61D1540 parser (pinned in #3237/#3251).
SUFFIX_SHIFTS = {"K": 10, "M": 20, "G": 30, "T": 40}


# --- Records ---------------------------------------------------------------

class Record:
    """One 0x30-byte record {key: str, a: u64, b: u64}."""

    SIZE = 0x30

    def __init__(self, key, a, b):
        self.key = key
        self.a = a
        self.b = b

    def __eq__(self, other):
        return (isinstance(other, Record) and self.key == other.key
                and self.a == other.a and self.b == other.b)

    def __repr__(self):
        return "Record(key=%r, a=%#x, b=%#x)" % (self.key, self.a, self.b)


def skiplist_record(a):
    """The record the SkipListFactory ctor registers."""
    return Record(SKIPLIST_RECORD_KEY, a, SKIPLIST_RECORD_B)


def hashlink_record(a):
    """The record the HashLinkListRepFactory ctor registers."""
    return Record(HASH_FACTORY_RECORD_KEY, a, HASH_RECORD_B)


class Holder:
    """A factory holder object: vtable, record vector, +0x20 field."""

    def __init__(self, vtable, size, records):
        self.vtable = vtable
        self.size = size
        self.records = list(records)  # the vector at +0x08

    @property
    def field_0x20(self):
        """The record's `a` field lives at holder+0x20."""
        return self.records[0].a if self.records else None


def build_skiplist_holder(a):
    """0x6064440: a 0x28-byte SkipListFactory with one record."""
    return Holder(SKIPLIST_FACTORY_VTABLE, SKIPLIST_HOLDER_SIZE,
                  [skiplist_record(a)])


def build_hashlink_holder(value, rsi=0, rdx=0x1000, rcx=1, r8=0x100):
    """0x605F150: a 0x40-byte HashLinkListRepFactory with one record.

    Layout: +0x20 = value, +0x28 = r8, +0x30 = rsi, +0x38 = rdx,
    +0x3c = rcx (low byte).
    """
    holder = Holder(HASH_FACTORY_VTABLE, HASH_HOLDER_SIZE,
                    [hashlink_record(value)])
    holder.field_0x28 = r8
    holder.field_0x30 = rsi
    holder.field_0x38 = rdx
    holder.field_0x3c = rcx
    return holder


# --- Shared_ptr installation (options +0x128/+0x130) ------------------------

class SharedPtrSlot:
    """The inline shared_ptr pair {object at +0x128, control at +0x130}."""

    def __init__(self):
        self.object = None
        self.control = None  # (vtable, size, counts_qword, embedded_object)

    def install_separate(self, holder):
        """Base init: 0x18-byte control pointing at the heap holder."""
        self.object = holder
        self.control = (SEPARATE_CONTROL_VTABLE, SEPARATE_CONTROL_SIZE,
                        REFCOUNT_ONE_ONE, holder)
        return self

    def install_inplace(self, holder):
        """Replacement: 0x38-byte inplace control, holder at +0x10."""
        self.object = holder
        self.control = (INPLACE_CONTROL_VTABLE, INPLACE_CONTROL_SIZE,
                        REFCOUNT_ONE_ONE, holder)
        return self

    def release_old(self):
        """0x5D350C0 on the old control when non-null (no-op here:
        the model tracks only that the release was invoked)."""
        if self.control is None:
            return False
        self.control = None
        return True


def replacement_gate_passes(name):
    """The 0x5D946B0 name gate. `name` is the current factory's
    Name() string. Returns True only when the rebuild runs.

    The gate compares min(len(name), 22) bytes against each literal
    and additionally requires len(name) == 22. Either 22-char hash
    factory name passes: "HashSkipListRepFactory" (0x432031) or
    "HashLinkListRepFactory" (0x43a3e1).
    """
    if name is None:
        return False
    length = len(name)
    if length != GATE_LENGTH:
        return False
    window = min(length, GATE_LENGTH)
    return (name[:window] == GATE_NAME_A[:window]
            or name[:window] == GATE_NAME_B[:window])


# --- Decimal parse (0x61D1540, via stub 0x61D1EF0) --------------------------

def parse_decimal(text):
    """Parse a decimal integer with an optional K/M/G/T suffix.

    Mirrors the 0x61D1540 behaviour pinned in #3237/#3251: leading
    digits, one optional suffix character shifting the value,
    throw on no digits or overflow. Returns the integer value.
    """
    if not text or not text[0].isdigit():
        raise ValueError("no digits in %r" % text)
    i = 0
    value = 0
    while i < len(text) and text[i].isdigit():
        value = value * 10 + int(text[i])
        if value > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("overflow in %r" % text)
        i += 1
    if i < len(text):
        suffix = text[i]
        if suffix not in SUFFIX_SHIFTS:
            raise ValueError("bad suffix %r in %r" % (suffix, text))
        value <<= SUFFIX_SHIFTS[suffix]
        if value > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("overflow in %r" % text)
        i += 1
    if i != len(text):
        raise ValueError("trailing characters in %r" % text)
    return value


# --- ":" setters ------------------------------------------------------------

def split_colon(text):
    """basic_string::find(":") then substr after it. Returns
    (found, head, tail). Raises ValueError (out_of_range,
    "basic_string::substr") when the tail start is past the end.
    """
    pos = text.find(":")
    if pos == -1:
        return False, text, None
    if pos + 1 > len(text):
        raise ValueError("basic_string::substr")
    return True, text[:pos], text[pos + 1:]


def setter_skip(text, slot):
    """0x61935B0: build a SkipListFactory holder from `text` and
    install it at slot[0], destroying the old holder through its
    vtable slot 1. `slot` is a one-element list holding the current
    holder (or None). Returns the new holder."""
    found, _head, tail = split_colon(text)
    value = parse_decimal(tail) if found else SKIP_DEFAULT_A
    new = build_skiplist_holder(value)
    old = slot[0]
    slot[0] = new
    if old is not None:
        old.destroyed_via_slot1 = True
    return new


def setter_hash(text, slot):
    """0x6193390: build a HashLinkListRepFactory from `text` and
    install it at slot[0], destroying the old one through its
    vtable slot 1."""
    found, _head, tail = split_colon(text)
    value = parse_decimal(tail) if found else HASH_DEFAULT_VALUE
    rsi, rdx, rcx, r8 = HASH_FIXED_ARGS
    new = build_hashlink_holder(value, rsi=rsi, rdx=rdx, rcx=rcx, r8=r8)
    old = slot[0]
    slot[0] = new
    if old is not None:
        old.destroyed_via_slot1 = True
    return new


# --- Registry accessors -----------------------------------------------------

def accessor(skip, index, value=None):
    """0x6192860 (skip=True) / 0x6192890: (out, value, index).
    index 0 stores a constant address; index 1 stores `value`;
    anything else stores nothing. Always returns 0."""
    entry = REGISTRY["skip_list" if skip else "hash_linkedlist"]
    if index == 0:
        return entry["accessor_index0"]
    if index == 1:
        return value
    return None
