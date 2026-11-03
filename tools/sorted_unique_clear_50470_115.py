"""Model of node #115 sorted-unique clear, 0x5d50470..0x5d506a8 (RE-001).

The routine clears one container (rdi = object, never returns normally:
it tail-jumps to 0x61bd0e0 with the object pointer). Object layout:
+0x00 head function pointer, +0x08/+0x10 its arguments, +0x18 chain
head, +0x20 flag byte, +0x28 pair-array begin, +0x30 pair-array end,
+0x38 pair-array capacity end. Each array element is 16 bytes: +0x00
argument qword, +0x08 disposer function pointer.

Order pinned from the disassembly: flag zero takes the free-only path
(no dispose, no virtual phase, head and chain untouched); flag nonzero
is cleared first, then the pair array is sorted ascending by unsigned
(first, second), adjacent duplicates are removed leaving one copy of
each distinct pair, each kept pair is disposed in sorted order by
calling its disposer with its argument, the array end is reset to
begin, the head (when non-null) is called with (+0x08, +0x10), the
+0x18 chain is walked (each node called with its +0x08/+0x10, then
deleted with size 0x20), +0x00 and +0x18 are zeroed, the buffer is
freed with size (+0x38 minus +0x28) when non-null, and the routine
tail-jumps. Duplicate copies beyond the new end are never disposed.
The sort-phase callees (0x5d4a3f0, 0x5d497e0) and the tail callee
(0x61bd0e0) are opaque here; the model implements the pinned
observable behavior (sorted unique order, once-each disposal).

An object is a dict with keys 'flag' (bool), 'pairs' (list of
(first, second) tuples, first/second unsigned ints; each element's
own +0x08 disposer is implicit),
'capacity_bytes' (int, the +0x38 minus +0x28 delete size),
'buffer_present' (bool, whether +0x28 is non-null), 'head'
(disposer id or None), 'head_args' (two-tuple), 'chain' (list of
{'func': id, 'args': two-tuple} dicts). The tracker is a dict with
'disposed' (list of (first, second) per disposed pair, in disposal
order), 'head_calls'
(list of (func, arg0, arg1)), 'chain_calls' (same shape) and
'chain_deleted' (list of delete sizes). The model never clears the
buffer pointer after freeing, mirroring the routine: a second clear
of a flag-cleared object frees the buffer again. Null object raises
NullObjectError: a model-only guard, not a binary claim (the binary
dereferences the pointer with no check).
"""


class NullObjectError(ValueError):
    pass


def clear_container(obj, tracker):
    if obj is None:
        raise NullObjectError("null object")
    if obj["flag"]:
        obj["flag"] = False
        pairs = sorted(obj["pairs"], key=lambda p: (p[0], p[1]))
        kept = []
        for pair in pairs:
            if kept and kept[-1][0] == pair[0] and kept[-1][1] == pair[1]:
                continue  # duplicate copy: never disposed
            kept.append(pair)
        for first, second in kept:
            tracker["disposed"].append((first, second))
        obj["pairs"] = []  # array end reset to begin
        if obj["head"] is not None:
            a, b = obj["head_args"]
            tracker["head_calls"].append((obj["head"], a, b))
        for node in obj["chain"]:
            a, b = node["args"]
            tracker["chain_calls"].append((node["func"], a, b))
            tracker["chain_deleted"].append(32)  # 0x20 per node
        obj["head"] = None
        obj["chain"] = []
    freed = obj["capacity_bytes"] if obj["buffer_present"] else None
    return {"freed_bytes": freed, "tail": True}
