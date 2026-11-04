"""Node #115 indexed call loop (0x5f6b520), the driver that calls its
callee once per index.

RE-001 work item. This is a complete behavior, not a lone-window
fragment: the whole 97-byte driver is modelled end to end, with its
sole caller site (0x5d607a9) recorded in the packet and its callee
0x5f6b000 taken as an oracle. The driver is the loop's only
observable effect: the sequence of callee calls it makes.

Native layout (all offsets from the disassembly of
work/hl-node-115.bin, bound to provenance/artifacts.json digest
a6e2897c...5301):

  indexed_call_loop(obj, a, b, c, flag, callee):
    count = signed32(obj + 0x54), read at entry.
    If count <= 0: return at once. No callee call, no other field
    read.
    Otherwise loop with index starting at 0:
      call callee(obj, a, b, c, flag, index) at site 0x5f6b565.
      The same obj, a, b, c and flag go to every call; only the
      index changes, in order 0, 1, 2, .... The flag passed is the
      low byte of the incoming flag only (movzbl %r8b at entry),
      so upper bits are ignored.
      Increment the index, re-read count from obj + 0x54, and
      continue exactly while the re-read count is strictly
      greater than the incremented index (signed comparison).
    With a stable count N > 0 this makes exactly N calls, indices
    0..N-1. Because the count is re-read after every call, a
    callee that raises the count extends the run and a callee
    that lowers it to at most the next index ends the run early;
    the model reproduces this because the callee receives the
    mutable object.

Assumptions recorded explicitly:
  * The object is a dict carrying "count" (the signed 32-bit field
    at +0x54); a missing field raises ValueError instead of
    faulting, which is model-only.
  * The callee callable stands in for 0x5f6b000; its own
    semantics are not claimed here, and neither are the meanings
    of a, b, c, the flag byte, or the count field beyond the loop
    bound.
  * The model does not reproduce register saves, the stack frame,
    or the two `ret` paths; the return is void in native code,
    and the model likewise returns None.
"""

MASK32 = 0xFFFFFFFF


def _signed32(value):
    value &= MASK32
    return value - (1 << 32) if value >= (1 << 31) else value


def indexed_call_loop(obj, a, b, c, flag, callee):
    """Run the driver. Returns None; the callee records the calls."""
    if "count" not in obj:
        raise ValueError("obj must carry 'count' (field at +0x54)")
    flag = flag & 0xFF
    if _signed32(obj["count"]) <= 0:
        return None
    index = 0
    while True:
        callee(obj, a, b, c, flag, index)
        index += 1
        if not (_signed32(obj["count"]) > index):
            return None
