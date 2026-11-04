"""Python model of node #115's adjacent field accessors at 0x5d8d0c0,
0x5d8d0d0 and 0x5d8d0e0.

RE-001 work item: research/work-items/RE-001-field-accessors-115/.
The three leaves are adjacent in the binary, each whole and each
with its own direct call sites (whole-file census, reproduced by
the packet's census.py):

* 0x5d8d0c0 (8 bytes: endbr64, mov, ret) takes an object in rdi
  and returns the dword at obj+0x70, zero-extended to 64 bits.
  It makes no calls and writes nothing.
* 0x5d8d0d0 (16 bytes: endbr64, mov, cmp, cmovb, mov, ret) takes
  (obj, value) in (rdi, esi) and stores the unsigned 32-bit
  maximum of the dword at obj+0x70 and value back at obj+0x70.
  The compare is ``cmp %esi,%eax`` followed by ``cmovb``: the
  move happens exactly when the current value is below the
  incoming value as unsigned 32-bit quantities, so equality
  stores nothing and the result is exactly max(current, value).
  It makes no calls and returns void.
* 0x5d8d0e0 (9 bytes: endbr64, mov, ret) takes an object in rdi
  and returns the qword at obj+0x18. It makes no calls and
  writes nothing.

The object is represented as a dict mapping byte offsets to
integer field values. A missing field raises ValueError; the
binary would simply read whatever bytes lie at that address, so
a missing field is a modelling gap, not a binary behavior. The
+0x70 value is masked to 32 bits and the +0x18 value to 64 bits,
matching the mov widths. The raise leaf's incoming value is
masked to 32 bits because the caller loads it into esi, which
zero-extends, and the leaf itself only ever compares and stores
32-bit quantities.

NOT claimed: what the objects or their +0x18/+0x70 fields denote,
any caller semantics beyond the call sites recorded in the
packet, or any relation between the three leaves beyond their
adjacency and their shared +0x70 field for the first two. The
+0x70 getter and the +0x70 raiser are the two halves of one
field's access pattern: the record-fill routine (open PR #2378)
reads the field through the getter, and the shared caller at
0x5f9dfa1 raises it through the raiser before raising two
other fields through the leaves of open PR #2374.
"""

MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1


def _require(obj, offset):
    if not isinstance(obj, dict) or offset not in obj:
        raise ValueError("missing field %#x" % offset)
    return obj[offset]


def get_field70(obj):
    """Return the dword at obj+0x70, zero-extended (0x5d8d0c0)."""
    return _require(obj, 0x70) & MASK32


def raise_field70(obj, value):
    """Store max(obj+0x70, value) unsigned 32-bit at obj+0x70.

    Returns void in the binary; here it returns None and the
    caller inspects obj[0x70]. (0x5d8d0d0)
    """
    current = _require(obj, 0x70) & MASK32
    incoming = value & MASK32
    if current < incoming:
        obj[0x70] = incoming
    else:
        obj[0x70] = current
    return None


def get_field18(obj):
    """Return the qword at obj+0x18 (0x5d8d0e0)."""
    return _require(obj, 0x18) & MASK64
