"""Python model of node #115 routine 0x5d55a20 (RE-001 work item).

The routine destroys the embedded object whose vptr lives at
object +0x10. It first compares the embedded object's vtable slot 0
against the derived complete destructor 0x5d55970 (the qword stored
at 0x64ed3f0): on a mismatch it tail-jumps to that slot-0 function
with the original object pointer; on a match it destroys the
embedded object inline — the derived destructor's steps applied to
the subobject at +0x10 — and tail-jumps to the base destructor
0x5fe70b0 with the subobject pointer.

The model follows the disassembly literally: every conditional
release, vptr write and tail jump below is a line in the
whole-function excerpt research/work-items/RE-001-wrapper-destructor-55a20-115/
main.txt. The release helper 0x5d350c0 is recorded by its contract
from the RE-001 three-release packet (null-skipped by the caller);
its internal body is not pinned here.

Arguments (System V): rdi = object.

Inline path, in order:
  [object +0x10] := 0x64d08a8 (derived table)
  release [object +0x48] via the helper when non-null
  [object +0x10] := 0x64cf200 (middle table)
  release [object +0x38] via the helper when non-null
  tail-jump to 0x5fe70b0 with rdi = object +0x10

The subobject's +0x38 field is object +0x48 and its +0x28 field is
object +0x38, which is why the inline path is exactly the derived
destructor (0x5d55970) applied at +0x10.
"""

DERIVED_DESTRUCTOR = 0x5D55970
DERIVED_TABLE = 0x64D08A8
MIDDLE_TABLE = 0x64CF200
GUARD_STORAGE = 0x64ED3F0
VTABLE_SLOT = 0x64C9840


class Subobject:
    """The embedded object at wrapper +0x10.

    slot0 is the embedded object's vtable slot-0 function value;
    field_48 and field_38 are the wrapper-relative pointers the
    inline path releases (subobject +0x38 and +0x28).
    """

    def __init__(self, slot0, field_48=None, field_38=None):
        self.slot0 = slot0
        self.field_48 = field_48
        self.field_38 = field_38
        self.vptr = None


class Wrapper:
    """The object passed in rdi; sub is the embedded object."""

    def __init__(self, sub):
        self.sub = sub
        self.released = []
        self.base_called_with = None
        self.dispatched_with = None


def destroy(wrapper, dispatch_fn):
    """Run the routine. Returns "dispatched" or "inlined".

    dispatch_fn is called with the wrapper itself (rdi unchanged)
    on the fallback path; it stands for the indirect tail jump to
    the embedded object's slot-0 function.
    """
    sub = wrapper.sub
    if sub.slot0 != DERIVED_DESTRUCTOR:
        dispatch_fn(wrapper)
        wrapper.dispatched_with = wrapper
        return "dispatched"
    sub.vptr = DERIVED_TABLE
    if sub.field_48 is not None:
        wrapper.released.append(sub.field_48)
    sub.vptr = MIDDLE_TABLE
    if sub.field_38 is not None:
        wrapper.released.append(sub.field_38)
    wrapper.base_called_with = sub
    return "inlined"
