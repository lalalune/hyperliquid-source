# RE-001: map node #115 shard allocation (0x5f117a0) with its TLS-shard, refill and global-lock paths

Task: RE-001 (#115 function map). Bounded question: how does the
outer object hand out an allocation — when does it use its
per-shard bump path, when does it refill a shard, and when does it
fall back to the global lock?

- Component: node #115 shard allocation, one whole function end to
  end, extracted from the digest-verified work binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  window `0x5f117a0..0x5f11c38` (1176 bytes; FDE .eh_frame offset
  0x745c7c, length 0x4c, CIE 0x730230, LSDA augmentation
  `93 80 02 ff` — the call-site table is not decoded in this
  packet).
- Claim status: observation for the window bounds, the rounding,
  the entry gate, the shard index arithmetic, the lock spins, the
  bump, the refill arms, the fallback throws and the cleanup pads;
  inference for the names "shard", "snapshot" and "gate pair"
  (they describe the observed roles, not proven source names);
  unresolved for the items listed in records.json (the refresh,
  post-direct and guard-release callees' internals, the meaning of
  field + 0x40 beyond its gate/grow roles, the direct path leaving
  the shard untouched, the TLS-gate semantics, the LSDA table).
- Note on evidence text: the raw disassembly excerpt is verbatim
  objdump output. Instruction mnemonics appearing in it (including
  `endbr64` at the window entry and at each landing pad) are
  genuine instructions present in the target binary, not
  placeholders; the packet checker re-verifies sampled instructions
  byte-for-byte against a fresh objdump run and the raw binary.
- Relationship to earlier work: no open PR covers this window
  (checked this cycle: open-PR snapshot of 125 open PRs, no
  0x5f117a0 title, and no 0x5f117a0 reference in the tree). The
  window is the fourth virtual (slot 0x64cc5f0) of the outer class
  whose destructor pair 0x5f10180/0x5f10d00 was mapped by the
  destructor-pair packet (vtable 0x64cc5d8 holds 0x5f10180,
  0x5f10d00, 0x5f11c40, 0x5f117a0, 0x5f04da0). It calls the member
  arena's AllocateAligned 0x605d7b0 at three sites, mapped by the
  arena packet; that packet's member destroy 0x605cc30 is the
  member at this + 0x60 used here. The window is reached only
  through its vtable slot: the census finds no direct call and no
  tail jump, and its single whole-file qword hit (file offset
  0x10bf10) is the addend field of the RELATIVE entry for slot
  0x64cc5f0, not a separate reference.

- The window, stated literally. Arguments: rdi = outer object,
  rsi = size, rdx = quantum, rcx = logger (only passed through to
  AllocateAligned). Rounded size: rbp = ((size - 1) | 7) + 1 in
  64-bit arithmetic, so size 0 rounds to 0. Entry gate: rax =
  field at this + 0x40, shifted right by 2; if that value is below
  the rounded size the window takes the global-lock path; otherwise
  it takes the TLS-shard path only when the quantum is zero, and
  the global-lock path when the quantum is nonzero.

- The global-lock path, stated literally. The byte at this + 0x950
  is spun on: PAUSE, re-check, and sched_yield once the pause
  counter passes 100, claimed with LOCK CMPXCHG of 1. Under the
  lock the window calls AllocateAligned (member at this + 0x60,
  rounded size, quantum, logger) via 0x605d7b0, then copies three
  snapshot fields (this + 0x958 <- this + 0x930, this + 0x960 <-
  this + 0x940, this + 0x968 <- this + 0x918), clears the global
  lock byte, and returns the AllocateAligned result.

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

- The shard bump, stated literally. When the entry remaining is at
  least the rounded size, the result is the old cursor, the cursor
  advances by the rounded size, the remaining shrinks by the
  rounded size, the shard lock byte is cleared, and the function
  returns that old cursor.

- The shard refill, stated literally. When the entry remaining is
  short, the global lock at this + 0x950 is acquired with the same
  spin shape. Then, if the snapshot remaining (this + 0x958) is at
  least the rounded size AND the member field pair (this + 0x888)
  equals (this + 0x8a8), the direct path runs: AllocateAligned
  (member, rounded size, quantum 0, logger) via 0x605d7b0, then
  the callee 0x5f07200 (called with this), the global lock byte
  cleared, the shard lock byte cleared, and the AllocateAligned
  result returned with the shard cursor and remaining untouched.
  Otherwise the grow path runs: with F = field at this + 0x40 and
  S = snapshot remaining, the grow size is F when S < F >> 1, S
  when F >> 1 <= S < 2 * F, and 2 * F otherwise. A fresh block is
  taken with AllocateAligned (member, grow size, 0, 0) and stored
  as the shard cursor; the three snapshot fields are refreshed
  from the member fields; the global lock byte is cleared; the
  bump then runs from the fresh block (cursor = block + size,
  remaining = grow - size in 64-bit arithmetic — the window
  performs no grow >= size check, so a smaller grow wraps the
  remaining literally); the shard lock byte is cleared; the block
  start is returned.

- The fallback path, stated literally. Reached only when the cpuid
  value is zero and shard-0 remaining is zero. When the global-lock
  slot is null the window throws system_error code 1; when the
  global-lock flag is already set it throws system_error code
  0x23 (35); otherwise it tries the global lock — success takes
  the global-lock path, and a lost race retries the shard
  selection.

- The cleanup, stated literally. Three landing pads (0x5f11c12,
  0x5f11c1b, 0x5f11c24) route to a shared cleanup: the global lock
  byte is cleared on one pad route, the guard-release callee
  0x5f0b5e0 is called on the shard-lock slot and/or the
  global-lock slot per the held flags, the stack canary is
  checked, and unwinding resumes with the exception in rbp.
