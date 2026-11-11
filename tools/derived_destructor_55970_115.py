"""Python model of the node #115 derived-class destructor pair at
0x5d55970 (complete-object destructor) and 0x5d559c0 (deleting
destructor), with the base destructor at 0x5fe70b0 (RE-001 work item).

Object layout (total size 0x48, the deleting destructor's self-free):

  +0x00  vptr (single slot, rewritten as destruction descends)
  +0x08  vector<string> begin (base member)
  +0x10  vector<string> end
  +0x18  vector<string> capacity end
  +0x28  refcounted pointer released at the middle stage (or None)
  +0x38  refcounted pointer released at the derived stage (or None)

Destruction order, identical in both variants:

  1. vptr := derived table (0x64d08a8). Release the +0x38 pointer
     through the shared refcount helper at 0x5d350c0 (null = no-op).
  2. vptr := middle table (0x64cf200). Release the +0x28 pointer
     through the same helper (null = no-op).
  3. Base destructor: vptr := base table (0x64d3430); tear down the
     vector<string> at +0x08/+0x10/+0x18 (below); free the vector
     buffer when its begin is non-null.
  4. Deleting variant only: sized-delete the object itself (0x48).

Vector<string> teardown (base destructor): each element is a 0x30-byte
string (data +0x00, size +0x08, capacity-or-inline-buffer +0x10). A
data pointer equal to the element's own +0x10 address is a short
string and frees nothing; any other data pointer is freed with the
sized delete using capacity + 1 (the heap allocation size including
the terminating NUL). After the elements, the vector buffer is freed
with (begin, capacity end minus begin) when begin is non-null; an
empty but non-null vector still frees its buffer.

Refcount helper (0x5d350c0, modelled by ``Ref``): the pointed-to
object carries its count at +0x08 as one 64-bit field. Releasing
decrements the strong count; when the strong count reaches zero the
managed object is destroyed through its vtable. The packed value
0x100000001 (strong 1, weak 1) takes the same destroy path after
zeroing the field. Whether the decrement is plain or atomic (chosen
by a global flag byte) does not change the observable outcome and is
not modelled.

A vector is a ``(begin_present, elements, buffer_size)`` triple where
``elements`` is a list of ``(is_heap, capacity)`` pairs (capacity
ignored for short strings) and ``buffer_size`` is capacity end minus
begin. A free is recorded as ``("elem", index, size)``,
``("buffer", size)``, ``("self", 0x48)``, or ``("destroy", ref_name)``
for a managed object destroyed by a release.
"""

DERIVED_VPTR = 0x64D08A8
MIDDLE_VPTR = 0x64CF200
BASE_VPTR = 0x64D3430
OBJECT_SIZE = 0x48
SPECIAL_PACKED = 0x100000001


class Ref:
    """A refcounted object released by the 0x5d350c0 helper."""

    def __init__(self, name, strong, weak=0):
        self.name = name
        self.packed = (weak << 32) | strong
        self.destroyed = False

    def release(self, frees):
        """Release one strong reference; destroy at zero."""
        if self.packed == SPECIAL_PACKED:
            self.packed = 0
            self.destroyed = True
            frees.append(("destroy", self.name))
            return
        strong = self.packed & 0xFFFFFFFF
        weak = self.packed >> 32
        strong -= 1
        self.packed = (weak << 32) | strong
        if strong == 0:
            self.destroyed = True
            frees.append(("destroy", self.name))


class Obj:
    """The 0x48-byte object torn down by the destructor pair."""

    def __init__(self, vec, ptr28=None, ptr38=None):
        self.vec = vec  # (begin_present, elements, buffer_size)
        self.ptr28 = ptr28
        self.ptr38 = ptr38
        self.vptr = None
        self.frees = []
        self.self_freed = False


def _base_destroy(obj):
    obj.vptr = BASE_VPTR
    begin_present, elements, buffer_size = obj.vec
    if not begin_present:
        if elements:
            raise ValueError("null vector begin with elements")
        return
    for index, (is_heap, capacity) in enumerate(elements):
        if is_heap:
            obj.frees.append(("elem", index, capacity + 1))
    obj.frees.append(("buffer", buffer_size))


def _shared_stages(obj):
    obj.vptr = DERIVED_VPTR
    if obj.ptr38 is not None:
        obj.ptr38.release(obj.frees)
    obj.vptr = MIDDLE_VPTR
    if obj.ptr28 is not None:
        obj.ptr28.release(obj.frees)


def complete_destroy(obj):
    """The 0x5d55970 variant: stages + base, no self-free."""
    _shared_stages(obj)
    _base_destroy(obj)
    return obj


def deleting_destroy(obj):
    """The 0x5d559c0 variant: stages + base + sized self-delete."""
    _shared_stages(obj)
    _base_destroy(obj)
    obj.frees.append(("self", OBJECT_SIZE))
    obj.self_freed = True
    return obj
