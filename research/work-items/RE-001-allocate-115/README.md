# RE-001: map node #115 outer allocation (0x5f11c40) with its dual-ended shard bump, refill and global-lock paths

Task: RE-001 (#115 function map). Bounded question: how does the
outer object's plain Allocate entry hand out memory — when does it
use its per-shard bump path, how do aligned and unaligned sizes
differ there, when does it refill a shard, and when does it fall
back to the global lock?

- Component: node #115 outer allocation, one whole function end to
  end, extracted from the digest-verified work binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  window `0x5f11c40..0x5f12162` (1314 bytes; FDE .eh_frame offset
  0x745ccc, length 0x50, CIE 0x730230, LSDA augmentation
  `70 80 02 ff` — the call-site table is not decoded in this
  packet).
- Claim status: observation for the window bounds, the entry gate,
  the shard index arithmetic, the lock spins, the dual-ended bump,
  the refill arms, the global top carve, the fallback throws and
  the cleanup pads; inference for the names "shard", "snapshot",
  "gate pair" and "current block" (they describe the observed
  roles, not proven source names); unresolved for the items listed
  in records.json (the refresh, post-direct and guard-release
  callees' internals, the meaning of field + 0x40 beyond its
  gate/grow roles, the direct path leaving the shard untouched,
  the TLS-gate semantics, the LSDA table).
- Note on evidence text: the raw disassembly excerpt is verbatim
  objdump output. Instruction mnemonics appearing in it (including
  `endbr64` at the window entry and at each landing pad) are
  genuine instructions present in the target binary, not
  placeholders; the packet checker re-verifies sampled instructions
  byte-for-byte against a fresh objdump run and the raw binary.
- Relationship to earlier work: no open PR covers this window
  (checked this cycle: open-PR snapshot of 139 open PRs, no
  0x5f11c40 title, and no 0x5f11c40 reference in the tree beyond
  the vtable slot lists). The window is the third virtual (slot
  0x64cc5e8) of the outer class whose destructor pair
  0x5f10180/0x5f10d00 was mapped by the destructor-pair packet
  (vtable 0x64cc5d8 holds 0x5f10180, 0x5f10d00, 0x5f11c40,
  0x5f117a0, 0x5f04da0). It calls the member arena's slow window
  0x605d6c0 and AllocateAligned 0x605d7b0, both mapped by the
  arena packet; its shard refresh 0x605e170, post-direct 0x5f07200
  and guard release 0x5f0b5e0 are cited by contract, as in the
  sibling shard-allocation packet. That sibling (0x5f117a0,
  AllocateAligned) shares this window's gate, shard selection,
  refill gates and grow instruction shape; the difference this
  window adds is the single-argument entry with no rounding and
  the dual-ended bump below.

- The window, stated literally. Arguments: rdi = outer object,
  rsi = size (raw — no rounding, no quantum argument). Entry gate:
  rax = field at this + 0x40, shifted right by 2; if that value is
  below the size the window takes the global-lock path; otherwise
  it takes the TLS-shard path.

- The global-lock path, stated literally. The byte at this + 0x950
  is spun on: PAUSE, re-check, and sched_yield once the pause
  counter passes 100, claimed with LOCK CMPXCHG of 1. Under the
  lock the current block is carved from the TOP: when the current
  remaining (this + 0x930) covers the size, the result is the
  current cursor (this + 0x920) minus the size, and both the
  cursor and the remaining shrink by the size; the three snapshot
  fields are then refreshed (this + 0x958 <- this + 0x930,
  this + 0x960 <- this + 0x940, this + 0x968 <- this + 0x918),
  the global lock byte is cleared, and the result is returned.
  When the current remaining is short, the slow callee 0x605d6c0
  (member at this + 0x60, size, consume 0) runs instead, and its
  result is returned after the same snapshot refresh and lock
  clear.

- The TLS-shard path, stated literally. The TLS slot at fs:0 -
  0x408 holds a cpuid value; the TLS getter (PLT 0x63f13b0) runs
  first only when GOT slot 0x64ed7e8 is nonzero, otherwise the slot
  is read directly. When the cpuid value is zero, the shard-0
  remaining field (array + 0x38) is checked: zero takes the
  fallback path below, nonzero continues with shard 0. The shard
  index is the cpuid masked to the low (byte at this + 0x50) bits
  — the shift count is the x86 CL value, so a shift of 64 or more
  uses shift & 63 — and the shard entry is the array pointer at
  this + 0x48 plus index * 64. Each entry is 64 bytes: lock byte
  at + 0x28, cursor at + 0x30, remaining at + 0x38. A shard whose
  lock byte is already set is refreshed by the callee 0x605e170
  (called with this); its return becomes the shard entry, and the
  entry lock is then spun on with the same PAUSE/yield/CMPXCHG
  shape. A failed LOCK CMPXCHG on an entry lock re-runs the
  refresh callee.

- The shard bump, stated literally — dual-ended. When the entry
  remaining is at least the size, the remaining shrinks by the
  size in both arms, but the result and the cursor differ. When
  the size is a multiple of 8, the result is the old cursor, the
  cursor advances by the size, and the shard lock byte is cleared
  (a front carve). When the size is not a multiple of 8, the
  result is cursor + new remaining — the tail of the free region
  — the cursor is left untouched, and the shard lock byte is
  cleared (a back carve). The back carve is what keeps the front
  cursor 8-aligned: an unaligned size never moves the front, so a
  later aligned size still starts aligned. Size 0 takes the front
  arm and returns the cursor without consuming anything.

- The shard refill, stated literally. When the entry remaining is
  short, the global lock at this + 0x950 is acquired with the same
  spin shape. Then, if the snapshot remaining (this + 0x958) is at
  least the size AND the member field pair (this + 0x888) equals
  (this + 0x8a8) AND the second gate pair (this + 0x8d8) equals
  (this + 0x8f8), the direct path runs: when the current remaining
  (this + 0x930) covers the size it is top-carved exactly like the
  global path, then the callee 0x5f07200 (called with this) runs,
  the global lock byte is cleared, the shard lock byte is cleared,
  and the carved pointer is returned with the shard cursor and
  remaining untouched; when the current remaining is short the
  slow callee 0x605d6c0 runs first and its result goes through the
  same post-direct step. Otherwise the grow path runs: with
  F = field at this + 0x40 and S = snapshot remaining, the grow
  size is F when S < F >> 1, S when F >> 1 <= S < 2 * F, and F
  again when S >= 2 * F — the cmovb only replaces F with S while
  S < 2 * F, so the register still holds F on the third arm
  (this matches the sibling window 0x5f117a0's identical
  instruction shape; its packet summary states 2 * F for that arm,
  but the excerpt bytes in both packets show F). A fresh block is
  taken with AllocateAligned (member, grow size, 0, 0) and stored
  as the shard cursor; the three snapshot fields are refreshed
  from the member fields; the global lock byte is cleared; the
  bump then runs from the fresh block (the available amount is the
  grow size, so a smaller grow wraps the remaining literally —
  the window performs no grow >= size check); the shard lock byte
  is cleared; the bump result is returned.

- The fallback path, stated literally. Reached only when the cpuid
  value is zero and shard-0 remaining is zero. When the
  global-lock slot is null the window throws system_error code 1;
  when the global-lock flag is already set it throws system_error
  code 0x23 (35) — that arm is unreachable from this entry, since
  the flag is zero on this route, and it is recorded literally;
  otherwise it tries the global lock — success takes the
  global-lock path body, and a lost race retries the shard
  selection.

- The cleanup, stated literally. Three landing pads (0x5f1213f,
  0x5f12148, 0x5f12151) route to a shared cleanup: the global lock
  byte is cleared on one pad route, the guard-release callee
  0x5f0b5e0 is called on the shard-lock slot and/or the
  global-lock slot per the held flags, the stack canary is
  checked, and unwinding resumes with the exception in rbp.
