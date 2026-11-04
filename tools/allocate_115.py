"""Node #115 outer allocation (window 0x5f11c40) — literal model.

The window is the third virtual of the outer class whose destructor
pair 0x5f10180/0x5f10d00 was mapped by the destructor-pair packet
(vtable 0x64cc5d8 holds 0x5f10180, 0x5f10d00, 0x5f11c40, 0x5f117a0,
0x5f04da0). It takes a single argument: rdi = outer object,
rsi = size. Unlike its sibling 0x5f117a0 (AllocateAligned, which
rounds the size and takes a quantum and a logger), this window uses
the raw size and no quantum: it is the plain Allocate entry.

Entry route: the TLS-shard path runs only when (field +0x40) >> 2
is at least the size; every other case takes the global-lock path
(byte at this + 0x950, PAUSE spin with sched_yield once the pause
counter passes 100, LOCK CMPXCHG of 1).

Global-lock path: the shared current block is carved from the TOP:
when its remaining (this + 0x930) covers the size, the result is
cursor (this + 0x920) minus the size, and both the cursor and the
remaining shrink by the size; the three snapshot fields are then
refreshed (this + 0x958 <- this + 0x930, this + 0x960 <-
this + 0x940, this + 0x968 <- this + 0x918), the global lock byte
is cleared, and the result is returned. When the current remaining
is short, the slow callee 0x605d6c0 (member at this + 0x60, size,
consume 0, mapped by the arena packet) runs instead, and its result
is returned after the same snapshot refresh.

TLS-shard path: the TLS slot at fs:0 - 0x408 holds a cpuid value;
a nonzero GOT slot 0x64ed7e8 gates a call to the TLS getter
(0x63f13b0) first, otherwise the slot is read directly. When the
cpuid value is zero, the shard-0 remaining field (array + 0x38) is
checked instead: zero takes the fallback path below. The shard
index is cpuid masked to the low (byte at this + 0x50) bits — the
shift count is the x86 CL value, so shift >= 64 uses shift & 63 —
and the shard entry is the array pointer at this + 0x48 plus
index * 64. Each entry is 64 bytes: lock byte at + 0x28, cursor at
+ 0x30, remaining at + 0x38.

A shard whose lock byte is already set is refreshed by the callee
0x605e170(this) (by contract: its internals are not modelled here
and its return becomes the shard entry); the entry lock is then
spun on the same way. A failed LOCK CMPXCHG on an entry lock
re-runs the refresh callee.

Shard bump (dual-ended — the behaviour that distinguishes this
window from AllocateAligned): when the entry remaining covers the
size, the remaining shrinks by the size in both arms, but the
result and the cursor differ. When the size is a multiple of 8 the
result is the old cursor and the cursor advances by the size (a
front carve, keeping the cursor 8-aligned). When the size is not a
multiple of 8 the result is cursor + new remaining — the tail of
the free region — and the cursor is left untouched (a back carve,
so an unaligned size never misaligns the front cursor). Either
way the shard lock byte is cleared and the result is returned.

Shard refill: under the global lock, when the snapshot remaining
(this + 0x958) covers the size AND the member gate pair
(this + 0x888) == (this + 0x8a8) AND the second gate pair
(this + 0x8d8) == (this + 0x8f8), the direct path runs: when the
current remaining (this + 0x930) covers the size it is top-carved
exactly like the global path, the callee 0x5f07200(this) (by
contract) runs, the global lock byte is cleared, the shard lock
byte is cleared, and the carved pointer is returned with the shard
cursor and remaining untouched; when the current remaining is
short the slow callee 0x605d6c0 runs first and its result goes
through the same post-direct step. Otherwise the grow path runs:
a fresh block of grow_size(F, S) bytes comes from AllocateAligned
(member at this + 0x60, grow, 0, 0) via 0x605d7b0, is stored as the
shard cursor, the three snapshot fields are refreshed from the
member fields, the global lock byte is cleared, and the bump above
runs from the fresh block (its available amount is the grow size,
so a grow smaller than the size wraps the remaining literally —
the window performs no grow >= size check).

Grow size, stated literally from the instruction shape (mov F;
shr; cmp; cmovb — the same shape as the sibling window 0x5f117a0):
with F = field + 0x40 and S = snapshot remaining, g = F when
S < F >> 1, g = S when F >> 1 <= S < 2 * F, and g = F again when
S >= 2 * F (the cmovb only replaces F with S while S < 2 * F, so
the register still holds F on the third arm).

Fallback path (cpuid zero and shard-0 remaining zero): a null
global-lock slot throws system_error code 1; an already-set
global-lock flag throws system_error code 0x23 (35) — that arm is
unreachable from this entry, since the flag is zero on this route,
and it is recorded literally; otherwise the global lock is tried:
success takes the global-lock path body, and a lost race retries
the shard selection.

Cleanup: three landing pads route to a shared cleanup that clears
the global lock byte on one route, calls the guard-release callee
0x5f0b5e0 (by contract) on the shard-lock slot and/or the
global-lock slot per the held flags, checks the stack canary, and
resumes unwinding. The LSDA call-site table is not decoded in the
packet.
"""

MASK64 = (1 << 64) - 1


def shard_index(cpuid, shift_byte):
    """Shard index from a cpuid value and the shift byte at +0x50."""
    k = shift_byte & 63
    return cpuid & ((1 << k) - 1)


def entry_route(field40, size):
    """'tls' when (field40 >> 2) >= size, else 'global'."""
    return "tls" if (field40 >> 2) >= size else "global"


def grow_size(field40, snapshot_remaining):
    """Grow size g from field +0x40 (F) and snapshot remaining (S)."""
    f = field40 & MASK64
    s = snapshot_remaining & MASK64
    if s < (f >> 1):
        return f
    if s < ((2 * f) & MASK64):
        return s
    return f


def shard_bump(cursor, remaining, size):
    """Shard bump: None when short, else (result, cursor, remaining).

    Aligned sizes carve from the front (cursor advances); unaligned
    sizes carve from the back (cursor untouched, result is the tail).
    """
    if remaining < size:
        return None
    new_remaining = (remaining - size) & MASK64
    if size & 7 == 0:
        return (cursor, (cursor + size) & MASK64, new_remaining)
    return ((cursor + new_remaining) & MASK64, cursor, new_remaining)


def current_carve(end, remaining, size):
    """Current-block top carve: None when short, else (result, end, remaining)."""
    if remaining < size:
        return None
    new_end = (end - size) & MASK64
    return (new_end, new_end, (remaining - size) & MASK64)


def refill_route(snapshot_remaining, size, gate888, gate8a8,
                 gate8d8, gate8f8, current_remaining):
    """Refill route: 'direct', 'slow' (slow + post-direct) or 'grow'."""
    if snapshot_remaining < size:
        return "grow"
    if gate888 != gate8a8:
        return "grow"
    if gate8d8 != gate8f8:
        return "grow"
    if current_remaining < size:
        return "slow"
    return "direct"


def fallback_decision(lock_slot_null, lock_flag_set):
    """Fallback throws: 1 for a null slot, 0x23 for a set flag, else None."""
    if lock_slot_null:
        return 1
    if lock_flag_set:
        return 0x23
    return None


class Shard:
    """One 64-byte shard entry: lock byte, cursor, remaining."""

    def __init__(self, cursor=0, remaining=0):
        self.cursor = cursor
        self.remaining = remaining
        self.locked = False


class Allocator:
    """Outer object state plus stub callees, for end-to-end tests."""

    def __init__(self, field40=0, shift=0, shards=None):
        self.field40 = field40
        self.shift = shift
        self.shards = shards if shards is not None else []
        self.cur_end = 0
        self.cur_remaining = 0
        self.snap_remaining = 0
        self.snap_940 = 0
        self.snap_counter = 0
        self.member_940 = 0
        self.member_counter = 0
        self.gate888 = 0
        self.gate8a8 = 0
        self.gate8d8 = 0
        self.gate8f8 = 0
        self.global_locked = False
        self.calls = []
        self.next_block = 0x10000

    def arena_allocate(self, size):
        """Stub for AllocateAligned(member, size, 0, 0): fresh block."""
        block = self.next_block
        self.next_block += max(size, 8)
        self.calls.append(("arena", size))
        return block

    def slow_allocate(self, size):
        """Stub for the slow callee 0x605d6c0(member, size, 0)."""
        self.calls.append(("slow", size))
        return self.arena_allocate(size)

    def post_direct(self):
        """Stub for the post-direct callee 0x5f07200(this)."""
        self.calls.append(("post_direct",))

    def allocate(self, size, cpuid=0):
        """Allocate(size) following the window's routes.

        Lock spins are abstracted (locks are taken as free); the
        callee stubs stand in for the mapped arena pair and the
        by-contract refresh/post-direct callees.
        """
        if entry_route(self.field40, size) == "global":
            self.global_locked = True
            carved = current_carve(self.cur_end, self.cur_remaining, size)
            if carved is None:
                # The slow callee's installed post-state belongs to the
                # arena packet's model; this stub leaves the fields
                # untouched and the snapshot below copies them as-is.
                result = self.slow_allocate(size)
            else:
                result, self.cur_end, self.cur_remaining = carved
            self.snap_remaining = self.cur_remaining
            self.snap_940 = self.member_940
            self.snap_counter = self.member_counter
            self.global_locked = False
            return result
        index = shard_index(cpuid, self.shift)
        shard = self.shards[index]
        bumped = shard_bump(shard.cursor, shard.remaining, size)
        if bumped is not None:
            result, shard.cursor, shard.remaining = bumped
            return result
        self.global_locked = True
        route = refill_route(self.snap_remaining, size, self.gate888,
                             self.gate8a8, self.gate8d8, self.gate8f8,
                             self.cur_remaining)
        if route == "direct":
            result, self.cur_end, self.cur_remaining = current_carve(
                self.cur_end, self.cur_remaining, size)
            self.post_direct()
        elif route == "slow":
            result = self.slow_allocate(size)
            self.post_direct()
        else:
            grow = grow_size(self.field40, self.snap_remaining)
            block = self.arena_allocate(grow)
            shard.cursor = block
            self.snap_remaining = self.cur_remaining
            self.snap_940 = self.member_940
            self.snap_counter = self.member_counter
            bumped = shard_bump(shard.cursor, grow, size)
            result, shard.cursor, shard.remaining = bumped
        self.global_locked = False
        return result
