"""Node #115 destructor pair for the class whose vtable is 0x64cc5d8.

Model of the two whole functions in research/work-items/
RE-001-destructor-pair-115/ (RE-001, #115 function map):

* 0x5f10180 (50 bytes) -- the base destructor: install the class
  vtable, destroy the member at +0x60, delete[] the array at +0x48
  when it is non-null, and return without freeing the object itself.
* 0x5f10d00 (60 bytes) -- the deleting destructor: the same steps,
  then a sized operator delete of the object itself (0x9b0 bytes).

The member destroy at 0x605cc30 (835 bytes, excerpted whole in the
packet) is modelled here as one step, not re-implemented: it installs
its own vtable 0x64d1fb8, destroys the +0x8e8 subobject through
0x605e8a0 when non-null, walks element arrays through the element
destroy 0x60d4f70, and sized-frees its arrays (0x200-byte entries and
8 * count array sizes). Its internals are a separate work item; the
pair's observable order -- member destroy, then array delete, then
(for the deleting form) self delete -- is what this model pins.

Nothing else about the class is claimed: fields other than +0x48 and
+0x60 are trivially destructible as far as these windows show, and the
class's source name is unknown.
"""

VPTR = 0x64CC5D8
MEMBER_OFFSET = 0x60
ARRAY_OFFSET = 0x48
OBJECT_SIZE = 0x9B0

BASE_DESTRUCTOR = 0x5F10180
DELETING_DESTRUCTOR = 0x5F10D00
MEMBER_DESTROY = 0x605CC30
MEMBER_VPTR = 0x64D1FB8
MEMBER_SUBOBJECT_OFFSET = 0x8E8
MEMBER_SUBOBJECT_DESTROY = 0x605E8A0
MEMBER_ELEMENT_DESTROY = 0x60D4F70


class Object:
    """The outer object as the two windows observe it.

    ``array`` is None for a null +0x48 pointer, otherwise an opaque
    token for the heap array. ``member`` is an opaque token for the
    subobject at +0x60. ``vptr`` starts unknown: neither window reads
    it, both overwrite it.
    """

    def __init__(self, array=None, member=None):
        self.vptr = None
        self.array = array
        self.member = member
        self.array_deleted = False
        self.freed = False
        self.freed_size = None


def destroy(obj, events, member_destroy):
    """The 0x5f10180 base destructor, in window order.

    ``events`` collects one tuple per observable step; ``member_destroy``
    is the caller's hook for the 0x605cc30 step (it receives the member
    token and the event list). Returns None, as the window does.
    """
    obj.vptr = VPTR
    events.append(("member_destroy", MEMBER_DESTROY, MEMBER_OFFSET))
    member_destroy(obj.member, events)
    if obj.array is not None:
        events.append(("delete_array", ARRAY_OFFSET))
        obj.array_deleted = True
        obj.array = None
    return None


def deleting_destroy(obj, events, member_destroy):
    """The 0x5f10d00 deleting destructor, in window order.

    Identical to :func:`destroy`, then a sized operator delete of the
    object itself (0x9b0 bytes). The window calls (not tail-jumps)
    the array delete, so the self delete runs after it in all cases.
    """
    destroy(obj, events, member_destroy)
    events.append(("sized_delete_self", OBJECT_SIZE))
    obj.freed = True
    obj.freed_size = OBJECT_SIZE
    return None
