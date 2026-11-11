#!/usr/bin/env python3
"""Python model of node #115 routine 0x5d5b3a0 (FDE 0x5d5b3a0..0x5d5b4b7).

The routine is a whole-object destructor for a holder at rdi. It
returns nothing, pushes rbp/rbx, reserves 8 bytes of stack and
performs no canary check. Phases, in order:

1. Member at +0x160: if non-null, released via the shared-release
   helper 0x5d350c0 (contract pinned in the #2737 packet).
2. Member at +0x110: passed to callee 0x60d5170 (callee body not
   pinned here; only the call is recorded).
3. List at +0xe8: every 0x18-byte plain node is freed by sized
   delete of exactly 0x18 via the _ZdlPvm PLT 0x63f0d80; the
   next pointer at node +0x00 is loaded before the free.
4. Buffer at +0xd8: memset(begin, 0, count * 8) via the memset
   PLT 0x63f0a90, where count is the qword at +0xe0; +0xf0 and
   +0xe8 are zeroed; unless begin equals the holder's own
   inline storage at +0x108, the buffer is freed by sized
   delete of (begin, count * 8).
5. Members at +0xd0, +0xc0, +0xb0, each in that order: if
   non-null, released via helper 0x5d350c0.
6. Sub-holder at +0x58: cleared by callee 0x5d5b300 (its list of
   0x50-byte two-string nodes is freed and its buffer zeroed,
   but its buffer is not freed there).
7. Buffer of the +0x58 sub-holder: begin at +0x58, count at
   +0x60; unless begin equals the sub-holder's own inline
   storage at +0x88, the buffer is freed by a tail jump to
   sized delete of (begin, count * 8).

The holder itself is never freed. Fields never read here
(+0x00..+0x58 except the members named, +0x68..+0xa8 except
+0xb0/+0xc0/+0xd0, +0xf8..+0x108 except +0x110, +0x118..+0x158
except +0x160) have no role claimed for them.
"""

PLT_DELETE = 0x63F0D80
PLT_MEMSET = 0x63F0A90
HELPER_RELEASE = 0x5D350C0
MEMBER_CALL = 0x60D5170
SUB_CLEAR = 0x5D5B300
NODE_SIZE = 0x18
INLINE_DELTA = 0x30


class Holder:
    """Minimal holder state the model observes."""

    def __init__(self, member_160=None, member_110=False, nodes=(),
                 buf_begin=None, buf_count=0, member_d0=None,
                 member_c0=None, member_b0=None, sub_buf_begin=None,
                 sub_buf_count=0):
        self.member_160 = member_160
        self.member_110 = member_110
        self.nodes = list(nodes)
        self.buf_begin = buf_begin
        self.buf_count = buf_count
        self.member_d0 = member_d0
        self.member_c0 = member_c0
        self.member_b0 = member_b0
        self.sub_buf_begin = sub_buf_begin
        self.sub_buf_count = sub_buf_count


def destruct(holder, inline_base=0x1000):
    """Return the ordered observable-effect trace for `holder`.

    `inline_base` stands for the holder address: the +0xd8
    buffer's inline storage is inline_base + 0x108 and the
    +0x58 sub-holder's inline storage is inline_base + 0x88.
    Effects are tuples; a "call" to a helper records its
    target and argument kind, not the helper's internals.
    """
    trace = []
    if holder.member_160 is not None:
        trace.append(("release", HELPER_RELEASE, "+0x160"))
    if holder.member_110:
        trace.append(("call", MEMBER_CALL, "+0x110"))
    for node in holder.nodes:
        trace.append(("free_node", PLT_DELETE, NODE_SIZE, node))
    # The buffer phase always runs: memset even for a null begin
    # with count 0, then the zeroing, then the free unless the
    # begin equals the inline storage address.
    trace.append(("memset", PLT_MEMSET, holder.buf_begin,
                  holder.buf_count * 8))
    trace.append(("zero", "+0xf0"))
    trace.append(("zero", "+0xe8"))
    if holder.buf_begin != inline_base + 0x108:
        trace.append(("free_buffer", PLT_DELETE, holder.buf_begin,
                      holder.buf_count * 8))
    for field, member in (("+0xd0", holder.member_d0),
                          ("+0xc0", holder.member_c0),
                          ("+0xb0", holder.member_b0)):
        if member is not None:
            trace.append(("release", HELPER_RELEASE, field))
    trace.append(("call", SUB_CLEAR, "+0x58"))
    if holder.sub_buf_begin != inline_base + 0x88:
        trace.append(("free_buffer_tail", PLT_DELETE,
                      holder.sub_buf_begin, holder.sub_buf_count * 8))
    return trace
