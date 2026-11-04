"""Model of node #115 routine 0x5d51c70: release of one composite object.

The routine takes one argument, the object pointer in rdi, and
performs four phases in order, with no writes to the object itself:

  1. single member at +0x20: if non-null, release it through the
     virtual slot at vtable offset +0x8 (an indirect call).
  2. vector at +0x08 (begin), +0x10 (end), +0x18 (capacity end):
     every non-null element, in order, released the same way
     (virtual slot +0x8); null slots are skipped, not released.
  3. vector buffer: if the begin pointer at +0x08 is non-null,
     operator delete is called on it with size equal to the
     capacity end (+0x18) minus begin, in bytes -- that is,
     capacity_slots * 8 for a pointer vector. If begin is null,
     no delete happens, even if the loop above was empty.
  4. head member at +0x00: if non-null, it is released through
     the same virtual slot +0x8, via a tail jump, so that release
     returns directly to this routine's caller. If null, the
     routine simply returns.

The release targets themselves are not modelled: the binary only
pins that the slot +0x8 function pointer is invoked, with the
member pointer as its argument, not what that function does
internally. The model is event-based: an object holds tokens
(strings) for the head, the single member, and the vector
elements, plus a buffer token and a capacity slot count.
release_object returns the ordered event list and leaves the
object unchanged.
"""

HEAD_OFFSET = 0x00
VECTOR_BEGIN_OFFSET = 0x08
VECTOR_END_OFFSET = 0x10
VECTOR_CAPACITY_OFFSET = 0x18
SINGLE_OFFSET = 0x20
VIRTUAL_RELEASE_SLOT = 0x08
ELEMENT_SIZE = 8


class ReleaseObject:
    """One composite object as the routine sees it.

    ``head`` and ``single`` are tokens (or None for null).
    ``elements`` is the vector contents in order, each a token or
    None for a null slot. ``buffer`` is the vector buffer token,
    or None when the begin pointer is null. ``capacity_slots``
    is the number of pointer slots allocated in the buffer.
    """

    def __init__(self, name, head=None, single=None, elements=(),
                 buffer=None, capacity_slots=0):
        for token in [head, single] + list(elements):
            if token is not None and not isinstance(token, str):
                raise TypeError("member/element token must be a string or None")
        if buffer is not None and not isinstance(buffer, str):
            raise TypeError("buffer token must be a string or None")
        if not isinstance(capacity_slots, int) or capacity_slots < 0:
            raise ValueError("capacity_slots must be a non-negative integer")
        elements = list(elements)
        if len(elements) > capacity_slots:
            raise ValueError("vector length exceeds capacity_slots")
        if buffer is None and (elements or capacity_slots):
            raise ValueError("a null begin pointer cannot carry elements"
                             " or capacity (the binary would not iterate"
                             " such a vector)")
        self.name = name
        self.head = head
        self.single = single
        self.elements = elements
        self.buffer = buffer
        self.capacity_slots = capacity_slots


def release_object(obj):
    """Return the ordered release events for ``obj``.

    The object is left unchanged: the routine writes no object
    slot; its only effects are the releases and the buffer delete.
    """
    if not isinstance(obj, ReleaseObject):
        raise TypeError("obj must be a ReleaseObject (the binary reads"
                        " +0x20 immediately, so a null object is not"
                        " a defined input)")
    events = []
    if obj.single is not None:
        events.append(("release", SINGLE_OFFSET, obj.single))
    for token in obj.elements:
        if token is not None:
            events.append(("release", VECTOR_BEGIN_OFFSET, token))
    if obj.buffer is not None:
        events.append(("delete_buffer", obj.buffer,
                       obj.capacity_slots * ELEMENT_SIZE))
    if obj.head is not None:
        events.append(("release_tail", HEAD_OFFSET, obj.head))
    return events
