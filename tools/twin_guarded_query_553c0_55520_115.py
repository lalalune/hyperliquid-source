"""Python model of the node #115 twin guarded queries (RE-001).

Routines: 0x5d553c0 (inner query 0x61b21f0) and 0x5d55520 (inner query
0x61b2760). The two bodies are instruction-identical except for their
branch/call targets and the inner callee, so one model covers both; the
inner query is a model input, not a claim, exactly as the evidence packet
describes it by call shape only.

Semantics pinned from the binary (see
research/work-items/RE-001-twin-guarded-query-553c0-55520-115/):

  1. The output record is zeroed at entry (int 0, tag 0, pointer null),
     unconditionally, before the flag check. An incoming pointer in the
     output slot is overwritten, not freed.
  2. Holder +0x650 null -> return the zeroed output: no mutex operation,
     no inner query call.
  3. Otherwise acquire the holder +0x658 mutex, re-read +0x650; a null
     re-read releases the mutex and returns the zeroed output.
  4. Otherwise call the inner query into a stack temp record, then move
     the temp into the output (int and tag copied, pointer moved; the
     temp slots are cleared). The code's conditional delete[] of the
     pre-move output pointer never fires, because step 1 zeroed that
     slot; the model records that the conditional free did not fire.
  5. Release the mutex and return the output pointer. Disposal of the
     returned pointer belongs to the caller (see probe_call).
  6. On an inner-query exception, the cleanup path releases the mutex
     (post-acquire region) and rethrows; the output stays zeroed.

Pointers are opaque tokens in this model; only identity (None vs a
token, and which token) is modelled, never addresses.
"""


class Triple:
    """A 16-byte record: int32 code, uint16 tag, pointer."""

    def __init__(self, code=0, tag=0, ptr=None):
        self.code = code
        self.tag = tag
        self.ptr = ptr

    def zero(self):
        self.code = 0
        self.tag = 0
        self.ptr = None


_UNSET = object()


class Holder:
    """The holder object: flag slot (+0x650) and mutex (+0x658).

    ``flag`` is the value read at entry; ``flag_at_reread`` is the value
    the twin sees after acquiring the mutex (defaults to ``flag``; pass
    None explicitly to model a null re-read).
    ``ops`` records mutex/inner-query events in order; ``freed``
    records pointers passed to operator delete[] by this model.
    """

    def __init__(self, flag, flag_at_reread=_UNSET):
        self.flag = flag
        self.flag_at_reread = flag if flag_at_reread is _UNSET else flag_at_reread
        self.locked = False
        self.ops = []
        self.freed = []


def guarded_query(holder, out, inner, key_struct, caller_arg, key16, pair16):
    """Run one twin guarded query. ``inner`` is the inner query callable.

    ``inner`` receives (flag_value, key_struct, caller_arg, key16,
    pair16) and returns a Triple. Returns ``out``.
    """
    out.zero()  # step 1: unconditional entry zeroing
    if holder.flag is None:  # step 2
        return out
    holder.locked = True
    holder.ops.append("acquire")  # step 3
    try:
        flag = holder.flag_at_reread
        if flag is None:  # step 4: re-read null
            return out
        temp = inner(flag, key_struct, caller_arg, key16, pair16)
        holder.ops.append("inner")  # step 5
        old_ptr = out.ptr  # always None after step 1: the conditional
        # delete[] in the binary never fires on this path.
        out.code = temp.code
        out.tag = temp.tag
        out.ptr = temp.ptr
        temp.zero()
        if old_ptr is not None:  # unreachable given step 1; kept for shape
            holder.freed.append(old_ptr)
        return out
    finally:
        # Normal path releases here; the exception path releases via the
        # cleanup fragment and rethrows (the output stays zeroed).
        if holder.locked:
            holder.locked = False
            holder.ops.append("release")


def probe_call(holder, out, inner, key_struct, caller_arg, key16, pair16):
    """Mirror one observed consumer call site (0x5ea300a / 0x5ea877a).

    Calls the twin with a stack output slot, then frees the returned
    pointer field when non-null (operator delete[]) without zeroing the
    slot afterwards, exactly as the callers do. Returns the freed
    pointer token, or None when nothing was freed.
    """
    guarded_query(holder, out, inner, key_struct, caller_arg, key16, pair16)
    if out.ptr is not None:
        freed = out.ptr
        holder.freed.append(freed)
        return freed
    return None
