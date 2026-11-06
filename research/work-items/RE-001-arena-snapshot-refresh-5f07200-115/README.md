# RE-001: map node #115 arena snapshot refresh (0x5f07200), the three-copy helper behind both allocation windows' direct paths

Task: RE-001 (#115 function map). Bounded question: what does the
callee 0x5f07200 — cited "by contract, internals not modelled" by
both merged allocation packets — actually do to the outer object?

- Component: node #115 arena snapshot refresh, one whole function
  end to end, extracted from the digest-verified work binary
  (SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  window `0x5f07200..0x5f0722f` (47 bytes; FDE .eh_frame offset
  0x3587e8, length 0x10, CIE 0x0, no augmentation data — the
  frames block is the header plus three DW_CFA_nop rows, so the
  window has no LSDA, no landing pads and no call-site table).
- Claim status: observation for the window bounds, the three
  copies and their order, the two call sites, the absence of any
  indirect reference, and the no-LSDA frame; inference for the
  names "snapshot refresh" and "snapshot/member" field roles
  (they are the caller packets' own terminology for these
  offsets); unresolved for the items listed in records.json
  (the meaning of member field + 0x940 beyond its snapshot role,
  the rationale for refreshing after the carve, and any snapshot
  readers outside the two mapped callers).
- Note on evidence text: the raw disassembly excerpt is verbatim
  objdump output. Instruction mnemonics appearing in it (including
  `endbr64` at the window entry) are genuine instructions present
  in the target binary, not placeholders; the packet checker
  re-verifies every instruction of the window byte-for-byte
  against a fresh objdump run and the raw binary.
- Relationship to earlier work: this window is the named unknown
  of two merged packets. RE-001-shard-allocate-115 (window
  0x5f117a0) calls it on its direct refill path and records
  "post-direct refresh, called with (this) after the direct
  AllocateAligned; internals not modelled"; RE-001-allocate-115
  (window 0x5f11c40) calls it on its direct path and records the
  same. The RE-002 vendor census registers this exact FDE
  interval (byte-windows id node115-vendor-5f07200) as a
  published-crate rebuild byte match for librocksdb-sys
  0.11.0+8.1.1 `rocksdb::ConcurrentArena::Fixup()` — identity and
  byte equality only; the merged RE-001 arena packet for
  AllocateAligned 0x605d7b0 is the standing precedent that a
  semantic packet coexists with a vendor window for the same
  interval. No open PR covers this window (checked this cycle:
  691 open PRs swept by title and branch, a title/body search for
  the address returns zero, and no file in the author's own 86
  open PRs or in the five nearest arena/snapshot PRs names the
  address or a packet for it).

- The window, stated literally. Argument: rdi = the outer object;
  no other argument register, stack slot, GOT slot or global is
  read, and no value is returned (rax is the copy scratch and
  holds the member counter on exit; neither caller reads it).
  The whole body is three 64-bit copies, in this order:

    this + 0x958 <- this + 0x930
    this + 0x960 <- this + 0x940
    this + 0x968 <- this + 0x918

  then ret. There are no calls, no branches, no lock or flag
  changes, and no other writes: the 24 destination bytes are the
  only state the window touches.

- Why it matters to the callers, stated literally. The three
  destinations are the snapshot triple both caller windows gate
  their refill decisions on (snapshot remaining at this + 0x958
  is compared against the requested size). The shard-allocation
  window performs the same three copies inline on its global-lock
  path and its grow path describes the step as "the three
  snapshot fields are refreshed from the member fields"; this
  helper is the shared form the two direct paths call instead —
  at 0x5f11b70 after the direct AllocateAligned and before either
  lock byte is cleared, and at 0x5f12083 after the carved pointer
  is stored and before the global lock byte at this + 0x950 is
  cleared. So on both direct paths the caller returns with the
  shard cursor and remaining untouched (as the caller packets
  state) but with the snapshot triple now mirroring the member
  fields — the half of the post-direct step those packets left
  unmodelled.

- Validation. The model (tools/arena_snapshot_refresh_5f07200_115.py)
  passes its 6 tests: the three copies land in window order,
  stale destinations are overwritten, sources and all other bytes
  are untouched, zero and full-width values copy verbatim, and a
  second run is a no-op. As an additional differential, the
  window's real 47 bytes were executed under Unicorn over 600
  randomised object images and the full 0x970-byte post-state
  matched the model every time (lane-side check; the packet
  checker below does not depend on it). The packet checker
  (verify.py) re-verifies the excerpt, every window instruction,
  the frames block, the census and the model tests against the
  digest-verified binary.
