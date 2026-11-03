"""Model of node #115 record copy, 0x5d4fce0..0x5d4fd97 (RE-001).

The routine copies one small record (rdi = destination, rsi = source,
returns void): a u32 field at +0x00, a u16 field at +0x04, and a heap
C-string pointer at +0x08 that is replaced by a fresh clone of the
source string (clone callee 0x61cf610..0x61cf64f: strlen, operator
new[] of length + 1, __strncpy_chk of length + 1 bytes). Bytes at
+0x06..+0x07 are never read or written.

Order pinned from the disassembly: the two scalar fields are copied,
then destination +0x08 is zeroed (dropping any prior destination
string WITHOUT a delete), then, only when the source string is
non-null, the clone runs and its pointer is stored. The post-clone
delete[] check reads the stack slot after it was zeroed, so it is
dead on the normal path; the landing-pad cleanup delete is likewise
vacuous because destination +0x08 is zero throughout the throwing
window. Both are modelled as no-ops and stated as observations, not
as separate behaviors.

A record is a dict with keys 'field32' (int), 'field16' (int),
'pad' (opaque value for bytes +0x06..+0x07, preserved untouched)
and 'text' (None, or an allocation id in the tracker). The tracker
is a dict with 'strings' (id -> str) and 'freed' (set of ids); the
model never frees, mirroring the routine. Null destination or source
raises NullRecordError: a model-only guard, not a binary claim (the
binary dereferences both pointers with no check).
"""


class NullRecordError(ValueError):
    """Raised when the model is given a null record pointer."""


def clone_string(text, tracker):
    """The 0x61cf610 clone: strlen + new[] + strncpy_chk of len + 1.

    Returns a fresh allocation id whose string equals the input.
    """
    new_id = f"alloc{len(tracker['strings'])}"
    tracker["strings"][new_id] = text
    return new_id


def copy_record(dest, src, tracker):
    """Copy src into dest following 0x5d4fce0 exactly.

    Returns a dict with 'dropped_old' (the prior destination string
    allocation id, or None) and 'freed' (always []: the routine frees
    nothing on the normal path, including the dropped old string).
    """
    if dest is None or src is None:
        raise NullRecordError("record copy on a null record pointer")
    dest["field32"] = src["field32"]
    dest["field16"] = src["field16"]
    # Prologue zero: the prior destination string is dropped here,
    # with no delete, before the clone runs.
    dropped_old = dest.get("text")
    dest["text"] = None
    if src.get("text") is not None:
        dest["text"] = clone_string(tracker["strings"][src["text"]],
                                    tracker)
    # Post-clone delete[] check: reads a zeroed stack slot, dead.
    return {"dropped_old": dropped_old, "freed": []}
