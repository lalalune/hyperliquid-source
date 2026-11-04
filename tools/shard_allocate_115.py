"""Node #115 shard allocation (window 0x5f117a0) — literal model.

The window is the fourth virtual of the outer class whose destructor
pair 0x5f10180/0x5f10d00 was mapped by the destructor-pair packet.
Arguments, as read: rdi = outer object, rsi = size, rdx = quantum,
rcx = logger (the logger is only passed through to AllocateAligned).

Entry rounding: rounded = ((size - 1) | 7) + 1 in 64-bit arithmetic,
so size 0 rounds to 0 (the sub wraps, the or fills, the add wraps).

Entry route: the TLS-shard path runs only when (field +0x40) >> 2 is
at least the rounded size AND the quantum is zero; every other case
takes the global-lock path (byte at this + 0x950, PAUSE spin with
sched_yield once the pause counter passes 100, LOCK CMPXCHG of 1).

Global-lock path: AllocateAligned(member at this + 0x60, rounded,
quantum, logger) via 0x605d7b0; then three snapshot fields are
copied (this + 0x958 <- this + 0x930, this + 0x960 <- this + 0x940,
this + 0x968 <- this + 0x918); the global lock byte is cleared and
the AllocateAligned result is returned.

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

Shard bump: when the entry remaining is at least the rounded size,
the result is the old cursor, the cursor advances by the size and
the remaining shrinks by the size, the shard lock is cleared, and
the function returns.

Shard refill (remaining short): the global lock is acquired, then
- snapshot remaining (this + 0x958) at least the size AND the
  member field pair (this + 0x888, this + 0x8a8) equal: the direct
  path — AllocateAligned(member, rounded, 0, logger), then the
  callee 0x5f07200(this) (by contract), the global lock cleared,
  the shard lock cleared, and the AllocateAligned result returned
  with the shard cursor/remaining untouched;
- otherwise the grow path — grow size g from field + 0x40 (F) and
  snapshot remaining (S): g = F when S < F >> 1, g = S when
  F >> 1 <= S < 2 * F, g = 2 * F otherwise; a fresh block is taken
  with AllocateAligned(member, g, 0, 0) and stored as the shard
  cursor; the three snapshot fields are refreshed from the member
  fields; the global lock is cleared; the bump then runs from the
  fresh block (cursor = block + size, remaining = g - size in
  64-bit arithmetic — the window performs no grow >= size check,
  so a grow smaller than the size wraps the remaining literally),
  the shard lock is cleared, and the block start is returned.

Fallback path (cpuid zero and shard-0 remaining zero): when the
global-lock slot is null the window throws system_error code 1;
when the global-lock flag is already set it throws system_error
code 0x23 (35); otherwise it tries the global lock — success takes
the global-lock path, a lost race retries the shard selection.

Cleanup: three landing pads route to a shared cleanup that clears
the global lock byte and conditionally calls the guard-release
callee 0x5f0b5e0 on the shard-lock slot and/or the global-lock
slot (by contract), then resumes unwinding. The LSDA call-site
table is not decoded in this packet.
"""

MASK64 = (1 << 64) - 1


def round_up8(size):
    """Rounded size exactly as the window computes it (64-bit)."""
    return ((((size - 1) & MASK64) | 7) + 1) & MASK64


def entry_route(field40, rounded, quantum):
    """'tls' or 'global' from the entry gate, stated literally."""
    if (field40 >> 2) >= rounded and quantum == 0:
        return "tls"
    return "global"


def shard_index(cpuid, shift):
    """Shard index: cpuid masked to the low (shift & 63) bits."""
    s = shift & 63
    if s == 0:
        return 0
    return cpuid & ((1 << s) - 1)


def grow_size(field40, snapshot_remaining):
    """Grow size g from field +0x40 (F) and snapshot remaining (S)."""
    if snapshot_remaining < (field40 >> 1):
        return field40
    if snapshot_remaining < 2 * field40:
        return snapshot_remaining
    return 2 * field40


def bump_allocate(cursor, remaining, size):
    """Shard bump: None when short, else (result, cursor, remaining)."""
    if remaining < size:
        return None
    return (cursor, (cursor + size) & MASK64, remaining - size)


def fallback_decision(lock_slot_null, global_flag_set):
    """Fallback error code, or None when it attempts the lock."""
    if lock_slot_null:
        return 1
    if global_flag_set:
        return 0x23
    return None


class Shard:
    """One 64-byte shard entry: lock byte, cursor, remaining."""

    def __init__(self, cursor=0, remaining=0, locked=False):
        self.cursor = cursor
        self.remaining = remaining
        self.locked = locked

    def bump(self, size):
        """Bump path; returns the allocated pointer or None."""
        out = bump_allocate(self.cursor, self.remaining, size)
        if out is None:
            return None
        result, self.cursor, self.remaining = out
        self.locked = False
        return result


class ShardAllocator:
    """Outer-object state for the window, with injected callees.

    arena_allocate(member_offset, size, quantum, logger) models
    0x605d7b0; refresh_shard(obj) models 0x605e170; post_direct(obj)
    models 0x5f07200. Snapshot/member fields are plain integers.
    """

    def __init__(self, field40=0, shards=None, arena_allocate=None,
                 refresh_shard=None, post_direct=None):
        self.field40 = field40
        self.shards = shards if shards is not None else []
        self.arena_allocate = arena_allocate or (lambda *a: 0)
        self.refresh_shard = refresh_shard or (lambda obj: 0)
        self.post_direct = post_direct or (lambda obj: None)
        # Member-arena fields (this + 0x930 / + 0x940 / + 0x918).
        self.member_remaining = 0
        self.member_940 = 0
        self.member_counter = 0
        # Snapshot fields (this + 0x958 / + 0x960 / + 0x968).
        self.snap_remaining = 0
        self.snap_940 = 0
        self.snap_counter = 0
        # Member gate pair (this + 0x888, this + 0x8a8).
        self.gate_a = 0
        self.gate_b = 0
        self.global_locked = False
        self.calls = []

    def _refresh_snapshots(self):
        self.snap_remaining = self.member_remaining
        self.snap_940 = self.member_940
        self.snap_counter = self.member_counter

    def allocate_global(self, rounded, quantum, logger):
        """Global-lock path: allocate, snapshot, unlock, return."""
        self.global_locked = True
        result = self.arena_allocate(0x60, rounded, quantum, logger)
        self.calls.append(("arena", 0x60, rounded, quantum, logger))
        self._refresh_snapshots()
        self.global_locked = False
        return result

    def allocate_shard(self, shard, size, logger):
        """Shard path for one locked entry; returns the pointer.

        Bump when the entry holds enough; otherwise the refill:
        direct when the snapshot covers the size and the gate pair
        is equal, else grow-and-bump from a fresh block.
        """
        if not shard.locked:
            raise ValueError("shard lock must be held on entry")
        bumped = shard.bump(size)
        if bumped is not None:
            return bumped
        self.global_locked = True
        if self.snap_remaining >= size and self.gate_a == self.gate_b:
            result = self.arena_allocate(0x60, size, 0, logger)
            self.calls.append(("arena", 0x60, size, 0, logger))
            self.post_direct(self)
            self.calls.append(("post_direct",))
            self.global_locked = False
            shard.locked = False
            return result
        grow = grow_size(self.field40, self.snap_remaining)
        block = self.arena_allocate(0x60, grow, 0, 0)
        self.calls.append(("arena", 0x60, grow, 0, 0))
        shard.cursor = block
        shard.remaining = grow
        self._refresh_snapshots()
        self.global_locked = False
        # Bump from the fresh block, literally (wrap if grow < size).
        result = shard.cursor
        shard.cursor = (block + size) & MASK64
        shard.remaining = (grow - size) & MASK64
        shard.locked = False
        return result
