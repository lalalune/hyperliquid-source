"""Python model of node #115's resolve-and-cache wrapper:
the wrapper at 0x5d8cf30 and its zero-id default leaf at
0x5d8ce80.

RE-001 work item: research/work-items/RE-001-resolve-115/.

Wrapper, stated literally. It takes an object in rdi and an id
dword in esi. It loads the subobject (the qword at obj+0x08)
and passes that subobject, not the original object, as rdi to
both callees. When the id dword is zero it calls the leaf at
0x5d8ce80, which returns the qword at subobject+0x118 and
writes nothing. When the id dword is nonzero it calls the
value lookup at 0x5d8ce90 (claimed by open PR #2403, not
re-claimed here); the model takes that callee as a callable
argument returning a value pointer, or 0 on a miss. On either
arm the wrapper stores the resolved value at obj+0x10 and at
obj+0x38 (the same value in both slots, including 0), and
returns 1 exactly when the resolved value is nonzero, else 0.
It writes nothing else and makes no other call.

Representation: an object is a dict with key "sub" (the
subobject dict) and, after a call, keys "slot_0x10" and
"slot_0x38". A subobject is a dict with key "default" (the
+0x118 qword). A missing object field raises ValueError; the
binary would simply read whatever bytes lie at that address,
so a missing field is a modelling gap, not a binary behavior.
The id is masked to its low 32 bits, matching the esi
register: an id whose low dword is zero takes the default
arm.

NOT claimed: what the object, its subobject, the ids or the
values denote; the value lookup's internals (see open PR
#2403); the identity of the function-pointer table containing
slot 0x64c9bc8, or which consumer loads that slot; caller
semantics beyond the census in the packet.
"""

MASK32 = (1 << 32) - 1


def default_leaf(subobject):
    """The leaf at 0x5d8ce80: return subobject+0x118."""
    if not isinstance(subobject, dict) or "default" not in subobject:
        raise ValueError("missing subobject +0x118 field")
    return subobject["default"]


def resolve(obj, obj_id, value_lookup):
    """The wrapper at 0x5d8cf30: resolve, cache, return bool.

    obj is an object dict, obj_id is the id dword, and
    value_lookup is a callable (subobject, id_dword) -> value
    standing in for the value lookup at 0x5d8ce90.
    Returns 1 when the resolved value is nonzero, else 0, and
    stores the resolved value at obj["slot_0x10"] and
    obj["slot_0x38"].
    """
    if not isinstance(obj, dict) or "sub" not in obj:
        raise ValueError("missing object +0x08 subobject")
    subobject = obj["sub"]
    id_dword = obj_id & MASK32
    if id_dword == 0:
        result = default_leaf(subobject)
    else:
        result = value_lookup(subobject, id_dword)
    obj["slot_0x10"] = result
    obj["slot_0x38"] = result
    return 1 if result != 0 else 0
