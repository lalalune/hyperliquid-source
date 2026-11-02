"""Model of node #94's WAL reader constructor, 0x51632f0..0x51633de.

Implements exactly the field writes pinned in
research/work-items/RE-001-wal-reader-ctor-94/records.json. The buffer
is a fresh 0x8000-byte object; the +0x88 string is the empty inline
form (pointer is the object's own +0x98 buffer, size 0). Types of the
source pair, the taken value and the rcx value are not pinned, so they
are carried verbatim as caller-supplied values.
"""

VTABLE_PTR = 0x575B0B8
STATIC_SLICE_PTR = 0x1E629B
BUFFER_SIZE = 0x8000
GLOBAL_FLAG_ADDR = 0x5777ED8


class RefCounted:
    """A caller-supplied object whose +0x08 field is its refcount."""

    def __init__(self, refcount=0):
        self.refcount = refcount


class TakenSlot:
    """A caller-supplied slot whose first qword the constructor moves."""

    def __init__(self, value=None):
        self.value = value


class WalReader:
    """The constructed reader object, as a field map."""

    def __init__(self):
        self.fields = {}

    def __getattr__(self, name):
        return self.fields[name]


def construct(source_first, source_second, taken_slot, rcx_value,
              flag_byte, log_number, global_flag_byte):
    """Build a WalReader exactly as 0x51632f0 does.

    source_second is a RefCounted or None; taken_slot is a TakenSlot
    whose value is moved and then cleared. global_flag_byte is the byte
    at 0x5777ed8: nonzero selects the plain add, zero the lock-add.
    Both forms increase the refcount by exactly 1; the model records
    which form was selected.
    """
    reader = WalReader()
    f = reader.fields
    f["vtable"] = VTABLE_PTR
    f["pair_first"] = source_first
    f["pair_second"] = source_second
    if source_second is not None:
        source_second.refcount += 1
        f["refcount_form"] = (
            "plain" if global_flag_byte != 0 else "lock")
    else:
        f["refcount_form"] = None
    f["taken"] = taken_slot.value
    taken_slot.value = None
    f["rcx_value"] = rcx_value
    f["flag_byte"] = flag_byte & 0xFF
    f["buffer"] = bytearray(BUFFER_SIZE)
    f["slice_ptr"] = STATIC_SLICE_PTR
    f["slice_len"] = 0
    f["flags_u16"] = 0
    f["field_0x50"] = 0
    f["field_0x58"] = 0
    f["field_0x60"] = 0
    f["log_number"] = log_number
    f["field_0x70"] = 0
    f["field_0x78"] = 0
    f["field_0x80"] = 0
    # Empty inline string: pointer is the object's own +0x98 buffer.
    f["string_ptr"] = "inline+0x98"
    f["string_len"] = 0
    f["string_first_byte"] = 0
    f["field_0xa8"] = 0
    f["field_0xb0"] = 0
    return reader
