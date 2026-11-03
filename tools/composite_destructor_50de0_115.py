"""Model of node #115 routine 0x5d50de0: a four-phase composite
destructor.

The routine takes one argument, the object pointer in rdi, and
destroys its contents in four phases, in order. It never frees the
object itself and never frees any chunk buffer; it only destroys
contents and resets the container state it owns.

Object fields the routine reads (all qwords):

  +0x00  first-chunk element count of the pointer vector (phase 4
         bound addend; zeroed at the end)
  +0x48  first-chunk buffer pointer of the pointer vector
  +0x50  second-chunk begin pointer of the pointer vector
  +0x58  second-chunk end pointer of the pointer vector
         (reset to the +0x50 begin pointer at the end)
  +0x68  first-chunk element count of the 0x30-byte element vector
         (phase 1 bound addend; drained to zero by phase 2)
  +0x1f0 first-chunk buffer pointer of the element vector
  +0x1f8 second-chunk begin pointer of the element vector
  +0x200 second-chunk end pointer of the element vector
         (reset to the +0x1f8 begin pointer at the end)

The four phases:

  1. Virtual-call walk over the element vector. The iteration
     count is (second-chunk byte size / 0x30) + the +0x68 count.
     Element i comes from the first chunk when i <= 7 and from
     the second chunk at index i - 8 otherwise. Each element is
     0x30 bytes: a string at +0x00 (pointer +0x00, size +0x08
     never read, capacity-or-inline-buffer +0x10), 8 unread
     bytes at +0x20, and a pointer at +0x28 to a struct whose
     +0x140/+0x148 delimit a 0x10-stride list. For each list
     entry, in order, the entry's first qword is its object
     pointer; the function pointer at vtable slot +0x100 is
     loaded, and when it differs from the sentinel 0x5d48450 it
     is called with (entry object, element address). Sentinel
     entries are skipped, not called.
  2. First-chunk string disposal, backwards. The +0x68 count is
     decremented to zero, one element at a time from the last to
     the first; each element's string is freed with operator
     delete (entry 0x63f0d80) with size capacity + 1 when its
     pointer differs from its own +0x10 slot address (heap
     string); a pointer equal to that slot address is an inline
     (SSO) string and nothing is freed.
  3. Second-chunk string disposal, forwards. Each second-chunk
     element's string is freed the same way (heap only, size
     capacity + 1), in order; then the +0x200 end pointer is
     reset to the +0x1f8 begin pointer.
  4. Pointer-vector teardown. The iteration count is
     (second-chunk byte size / 8) + the qword at +0x00. Pointer
     i comes from the first chunk when i <= 7 and from the
     second chunk at index i - 8 otherwise. Each non-null
     pointer is destroyed by the callee at 0x5d8d820 and then
     freed with operator delete with size 0x290. Finally the
     +0x00 qword is zeroed (when non-zero) and the +0x58 end
     pointer is reset to the +0x50 begin pointer (when they
     differ).

The callees' internals are not modelled: the binary pins only
that they are invoked, with these arguments, in this order.
The model is event-based: elements and pointers are tokens
(strings), and destroy_composite returns the ordered event list
plus the resulting container state. The object fields the
routine resets are reported as reset events, not silently
applied to the inputs.
"""

SENTINEL_SLOT = 0x5D48450
DELETE_ENTRY = 0x63F0D80
DESTROY_CALLEE = 0x5D8D820
POINTER_DELETE_SIZE = 0x290
ELEMENT_SIZE = 0x30
FIRST_CHUNK_SLOTS = 8


class DestructorError(ValueError):
    """Raised for inputs the binary could not walk as given."""


def _check_string(string, label):
    """Validate one (kind, pointer, capacity) string triple."""
    if not isinstance(string, tuple) or len(string) != 3:
        raise DestructorError("%s must be a (kind, pointer, capacity) triple"
                              % label)
    kind, pointer, capacity = string
    if kind not in ("heap", "inline"):
        raise DestructorError("%s kind must be 'heap' or 'inline'" % label)
    if not isinstance(pointer, str) or not pointer:
        raise DestructorError("%s pointer token must be a non-empty string"
                              % label)
    if kind == "heap":
        if not isinstance(capacity, int) or capacity < 0:
            raise DestructorError(
                "%s heap capacity must be a non-negative integer" % label)
    elif capacity is not None:
        raise DestructorError("%s inline string carries no capacity" % label)


def _check_entries(entries, label):
    """Validate one element's 0x10-stride entry list."""
    if not isinstance(entries, list):
        raise DestructorError("%s entries must be a list" % label)
    for entry in entries:
        if not isinstance(entry, tuple) or len(entry) != 2:
            raise DestructorError("%s entry must be (object, slot)" % label)
        obj, slot = entry
        if not isinstance(obj, str) or not obj:
            raise DestructorError("%s object token must be a string" % label)
        if not isinstance(slot, int):
            raise DestructorError("%s slot must be an integer" % label)


class Element:
    """One 0x30-byte element: a string plus a 0x10-stride list."""

    def __init__(self, name, string, entries=()):
        _check_string(string, name)
        _check_entries(list(entries), name)
        self.name = name
        self.string = string
        self.entries = list(entries)


class CompositeObject:
    """The object as routine 0x5d50de0 sees it.

    ``elem_first`` / ``elem_second`` are the element vector's
    first- and second-chunk element lists; ``elem_first_count``
    is the +0x68 count (phase 1 bound addend, drained by
    phase 2). ``ptr_first`` / ``ptr_second`` are the pointer
    vector's chunk lists of tokens (or None for null slots);
    ``ptr_first_count`` is the +0x00 qword (phase 4 bound
    addend, zeroed at the end).
    """

    def __init__(self, name, elem_first=(), elem_second=(),
                 elem_first_count=None, ptr_first=(), ptr_second=(),
                 ptr_first_count=None):
        self.name = name
        self.elem_first = list(elem_first)
        self.elem_second = list(elem_second)
        self.ptr_first = list(ptr_first)
        self.ptr_second = list(ptr_second)
        if elem_first_count is None:
            elem_first_count = len(self.elem_first)
        if ptr_first_count is None:
            ptr_first_count = len(self.ptr_first)
        for value, label in ((elem_first_count, "elem_first_count"),
                             (ptr_first_count, "ptr_first_count")):
            if not isinstance(value, int) or value < 0:
                raise DestructorError(
                    "%s must be a non-negative integer" % label)
        self.elem_first_count = elem_first_count
        self.ptr_first_count = ptr_first_count
        for token in self.ptr_first + self.ptr_second:
            if token is not None and (not isinstance(token, str)
                                      or not token):
                raise DestructorError(
                    "pointer token must be a string or None")
        for element in self.elem_first + self.elem_second:
            if not isinstance(element, Element):
                raise DestructorError("element vector holds Elements")


def _walk(first, second, first_count, label):
    """Yield the walked items in the binary's literal order.

    Item i comes from ``first`` when i <= 7, else from ``second``
    at index i - 8; the walk length is len(second) + first_count.
    Inputs that would read past a provided chunk raise, since
    the binary would read out of bounds there.
    """
    total = len(second) + first_count
    for i in range(total):
        if i <= 7:
            if i >= len(first):
                raise DestructorError(
                    "%s walk index %d past first chunk" % (label, i))
            yield first[i]
        else:
            j = i - FIRST_CHUNK_SLOTS
            if j >= len(second):
                raise DestructorError(
                    "%s walk index %d past second chunk" % (label, i))
            yield second[j]


def destroy_composite(obj):
    """Return the ordered event list for ``obj``'s destruction.

    Events: ("virtual_call", element name, object token) for
    each non-sentinel list entry; ("delete_string", pointer,
    capacity + 1) for each heap string; ("destroy", pointer)
    and ("delete_pointer", pointer, 0x290) per non-null pointer;
    ("reset_elem_count", 0), ("reset_elem_end",),
    ("clear_ptr_count", 0) and ("reset_ptr_end",) for the
    container-state resets. The inputs are left unchanged.
    """
    if not isinstance(obj, CompositeObject):
        raise TypeError("destroy_composite takes a CompositeObject")
    events = []
    # Phase 1: virtual-call walk, forwards, both chunks.
    for element in _walk(obj.elem_first, obj.elem_second,
                         obj.elem_first_count, "element vector"):
        for entry_obj, slot in element.entries:
            if slot != SENTINEL_SLOT:
                events.append(("virtual_call", element.name, entry_obj))
    # Phase 2: first-chunk strings, backwards, count drained.
    for index in range(obj.elem_first_count - 1, -1, -1):
        if index >= len(obj.elem_first):
            raise DestructorError(
                "phase 2 index %d past first chunk" % index)
        kind, pointer, capacity = obj.elem_first[index].string
        if kind == "heap":
            events.append(("delete_string", pointer, capacity + 1))
    events.append(("reset_elem_count", 0))
    # Phase 3: second-chunk strings, forwards, end reset.
    for element in obj.elem_second:
        kind, pointer, capacity = element.string
        if kind == "heap":
            events.append(("delete_string", pointer, capacity + 1))
    events.append(("reset_elem_end",))
    # Phase 4: pointer teardown, forwards, both chunks.
    for pointer in _walk(obj.ptr_first, obj.ptr_second,
                         obj.ptr_first_count, "pointer vector"):
        if pointer is not None:
            events.append(("destroy", pointer))
            events.append(("delete_pointer", pointer, POINTER_DELETE_SIZE))
    events.append(("clear_ptr_count", 0))
    events.append(("reset_ptr_end",))
    return events
