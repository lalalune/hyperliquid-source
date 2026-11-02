"""Model of node #94's WAL reader destructor, 0x5162ed0..0x51632af,
plus its deleting destructor 0x51632b0..0x51632cb.

Implements exactly the teardown pinned in
research/work-items/RE-001-wal-reader-dtor-94/records.json. Every
release is recorded as an event so tests can assert the exact order.
Object types behind the pointers are not pinned, so they are carried
as caller-supplied values; only the branch conditions and the call
shapes are modeled.
"""

VTABLE_PTR = 0x575B0B8
KNOWN_DELETING_DTOR = 0x5160EC0
KNOWN_VTABLE = 0x5766048
SUB_VTABLE_FIRST = 0x575F6A0
SUB_VTABLE_SECOND = 0x5759BC0
GLOBAL_FLAG_ADDR = 0x5777ED8
SENTINEL_WORD = 0x100000001
RELEASE_FN = 0x4F94A40
PREFIX_FREE_FN = 0x543BE20
FIELD18_DESTROY_FN = 0x55D9080
READER_SIZE = 0xB8
SUBOBJECT_SIZE = 0xA8
KNOWN_OBJECT_SIZE = 0x38


class Control:
    """A shared-count control block: vtable slot 0x10 disposes the
    managed object, slot 0x18 destroys the control. The count word
    packs (weak << 32 | strong) under the inferred reading."""

    def __init__(self, strong, weak):
        self.strong = strong
        self.weak = weak

    @property
    def word(self):
        return (self.weak << 32) | self.strong


class String:
    """A libstdc++-shaped string: data pointer, capacity, and its own
    inline buffer (identified by an id). Heap-allocated exactly when
    the pointer differs from the inline buffer."""

    def __init__(self, ptr, capacity, inline_buffer):
        self.ptr = ptr
        self.capacity = capacity
        self.inline_buffer = inline_buffer

    @property
    def is_heap(self):
        return self.ptr != self.inline_buffer


class SubObject:
    """The +0x18 taken object (168 bytes)."""

    def __init__(self, elements, array_begin, array_cap_end,
                 string60, ref50, obj40_deleting_dtor, ref28, string00):
        self.elements = elements  # list of Control or None
        self.array_begin = array_begin  # pointer id, or None
        self.array_cap_end = array_cap_end  # pointer id
        self.string60 = string60  # String
        self.ref50 = ref50  # Control or None
        self.obj40_deleting_dtor = obj40_deleting_dtor  # id or None
        self.ref28 = ref28  # Control or None
        self.string00 = string00  # String


class Obj78:
    """The +0x78 heap object (56 bytes)."""

    def __init__(self, deleting_dtor):
        self.deleting_dtor = deleting_dtor


class WalReader:
    """The reader object, as a field map."""

    def __init__(self, buffer30=False, obj78=None, prefix_a8=None,
                 prefix_b0=None, string88=None, buffer80=False,
                 sub18=None, ref10=None):
        self.buffer30 = buffer30
        self.obj78 = obj78
        # prefix fields are (pointer, prefix_byte) or None
        self.prefix_a8 = prefix_a8
        self.prefix_b0 = prefix_b0
        self.string88 = string88  # String or None
        self.buffer80 = buffer80
        self.sub18 = sub18  # SubObject or None
        self.ref10 = ref10  # Control or None


def release_control(ctrl, events, global_flag_byte, label):
    """The shared-count release protocol for one control pointer.

    Returns True exactly on the sentinel path. Only the reader's own
    +0x10 field treats that as a tail-destroy stop; sub-object callers
    ignore the return value and continue, as the binary does. The
    sentinel path records dispose + destroy; the old-strong-1 path
    records the release call (dispose, then weak decrement, then
    destroy only when the weak count reaches zero)."""
    if ctrl is None:
        events.append(("skip_null", label))
        return False
    if ctrl.word == SENTINEL_WORD:
        ctrl.strong = 0
        ctrl.weak = 0
        events.append(("dispose", label))
        events.append(("destroy_control", label))
        return True
    old_strong = ctrl.strong
    form = "plain" if global_flag_byte != 0 else "lock"
    ctrl.strong -= 1
    events.append(("decrement", label, form, old_strong))
    if old_strong == 1:
        events.append(("release_call", label, RELEASE_FN))
        events.append(("dispose", label))
        ctrl.weak -= 1
        if ctrl.weak == 0:
            events.append(("destroy_control", label))
    return False


def prefix_free(field, events, label):
    """Helper 0x543be20: null returns without an event; otherwise the
    freed address is pointer minus the byte stored at pointer - 1."""
    if field is None:
        events.append(("skip_null", label))
        return
    ptr, prefix_byte = field
    events.append(("prefix_free", label, PREFIX_FREE_FN, ptr - prefix_byte))


def free_string(string, events, label):
    """SSO string destroy: heap only, with size capacity + 1."""
    if string is None:
        events.append(("skip_null", label))
        return
    if string.is_heap:
        events.append(("sized_delete", label, string.ptr,
                       string.capacity + 1))
    else:
        events.append(("skip_inline", label))


def destroy_subobject(sub, events, global_flag_byte):
    """The +0x18 sub-object teardown, in exact order."""
    for element in sub.elements:
        release_control(element, events, global_flag_byte, "array_element")
    if sub.array_begin is not None:
        events.append(("array_buffer_delete", sub.array_begin,
                       sub.array_cap_end))
    events.append(("vtable_reset", SUB_VTABLE_FIRST))
    free_string(sub.string60, events, "sub_string60")
    release_control(sub.ref50, events, global_flag_byte, "sub_ref50")
    events.append(("vtable_reset", SUB_VTABLE_SECOND))
    if sub.obj40_deleting_dtor is not None:
        events.append(("virtual_delete", "sub_obj40",
                       sub.obj40_deleting_dtor))
    else:
        events.append(("skip_null", "sub_obj40"))
    release_control(sub.ref28, events, global_flag_byte, "sub_ref28")
    free_string(sub.string00, events, "sub_string00")
    events.append(("sized_delete", "subobject", SUBOBJECT_SIZE))


def destroy_reader(reader, global_flag_byte):
    """The complete destructor 0x5162ed0. Returns the event list."""
    events = []
    events.append(("vtable_install", VTABLE_PTR))
    if reader.buffer30:
        events.append(("delete_array", "buffer30"))
    else:
        events.append(("skip_null", "buffer30"))
    if reader.obj78 is None:
        events.append(("skip_null", "obj78"))
    elif reader.obj78.deleting_dtor != KNOWN_DELETING_DTOR:
        events.append(("virtual_delete", "obj78",
                       reader.obj78.deleting_dtor))
    else:
        events.append(("vtable_install", KNOWN_VTABLE))
        events.append(("call", FIELD18_DESTROY_FN, "obj78_field18"))
        events.append(("sized_delete", "obj78", KNOWN_OBJECT_SIZE))
    prefix_free(reader.prefix_a8, events, "prefix_a8")
    prefix_free(reader.prefix_b0, events, "prefix_b0")
    free_string(reader.string88, events, "string88")
    if reader.buffer80:
        events.append(("delete_array", "buffer80"))
    else:
        events.append(("skip_null", "buffer80"))
    if reader.sub18 is None:
        events.append(("skip_null", "sub18"))
    else:
        destroy_subobject(reader.sub18, events, global_flag_byte)
    tail = release_control(reader.ref10, events, global_flag_byte,
                           "ref10")
    if tail:
        events.append(("tail_destroy", "ref10"))
    return events


def deleting_dtor(reader, global_flag_byte):
    """The deleting destructor 0x51632b0: destroy, then free 0xb8."""
    events = destroy_reader(reader, global_flag_byte)
    events.append(("sized_delete", "reader", READER_SIZE))
    return events
