"""Model of node #115 routine 0x5d52b60: three-stage fallback lookup.

Pinned from the digest-verified node #115 binary
(SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The routine takes three arguments: an object pointer in rdi, a
query value in rsi, and an index in rdx. It returns one pointer,
resolved in order:

1. Callee: call 0x5d8ce30 with (query, index) -- the original
   rsi as the first argument and the original rdx as the second.
   A non-null result is returned at once; nothing else is read.
2. Array: read the pointer array at object +0xd10 and take
   entry [index] (8-byte stride, so the index is a pointer
   index, not a byte offset). A non-null entry is returned.
   The index used here is the value saved in rbx before the
   callee call, so it is the same index the callee received,
   even though the callee may clobber rdx.
3. Default: return the pointer at object +0xd08, whatever it
   is -- including null when the default slot itself is null.

The routine writes nothing and makes no other call. The three
returns share one epilogue; the return value is whatever rax
holds at that point.

NOT modelled: what the callee computes from (query, index),
what the object, the array, or the default slot denote, or
behaviour on dangling pointers. A null object raises, matching
the binary's unconditional reads of +0xd08/+0xd10 on the
miss paths; a null array pointer on the array path raises,
matching the binary's unconditional dereference of that
pointer plus the index. An out-of-range index is not given a
binary behaviour here: the binary reads past the array
unchecked, and the model raises instead.
"""

CALLEE = 0x5D8CE30
ARRAY_FIELD_OFFSET = 0xD10
DEFAULT_FIELD_OFFSET = 0xD08


def fallback_lookup(obj, query, index, callee):
    """Run the pinned behaviour.

    obj: dict with "array_0xd10" (list of entries, or None)
    and "default_0xd08" (opaque/None).
    query: opaque value passed to the callee as its first
    argument.
    index: integer used as the callee's second argument and as
    the array entry index.
    callee: callable(query, index) -> opaque/None, standing in
    for 0x5d8ce30, which is opaque here.

    Returns the resolved pointer (or None on the default path
    when the default slot is null).
    """
    if obj is None:
        raise ValueError("null object pointer")
    result = callee(query, index)
    if result is not None:
        return result
    array = obj["array_0xd10"]
    if array is None:
        raise ValueError("null array pointer at +0xd10")
    entry = array[index]
    if entry is not None:
        return entry
    return obj["default_0xd08"]
