# RE-001: map node #115 guard release (0x5f0b5e0), the lock-slot release behind both allocation windows' cleanup pads

Task: RE-001 (#115 function map). Bounded question: what does the
callee 0x5f0b5e0 — cited "guard release, internals not modelled"
by both merged allocation packets — actually do to the lock slot
it is handed and to the lock byte behind it?

- Component: node #115 guard release, one whole function end to
  end, extracted from the digest-verified work binary
  (SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  window `0x5f0b5e0..0x5f0b605` (37 bytes; FDE .eh_frame offset
  0x358bc8, length 0x10, CIE 0x0, no augmentation data — the
  frames block is the header plus two DW_CFA rows, so the window
  has no LSDA, no landing pads and no call-site table).
- Claim status: observation for the window bounds, the three
  control-flow arms and their exact write sets, the throw tail
  and its error code, the four call sites and their slot
  addresses, the absence of any indirect reference, and the
  no-LSDA frame; inference for the names "guard release",
  "device pointer" and "owns byte" (the first is the caller
  packets' own term for this callee; the layout names state the
  observed roles); unresolved for the items listed in
  records.json (which caller slot is the shard lock and which
  the global lock, the identity of the guarded lock bytes
  beyond their caller-side roles, and any reachability of the
  throw arm outside the mapped callers).
- Note on evidence text: the raw disassembly excerpt is verbatim
  objdump output. Instruction mnemonics appearing in it
  (including `endbr64` at the window entry) are genuine
  instructions present in the target binary, not placeholders;
  the packet checker re-verifies every instruction of the
  window byte-for-byte against a fresh objdump run and the raw
  binary.
- Relationship to earlier work: this window is the last of the
  three named callee unknowns of the two merged allocation
  packets (the other two, 0x605e170 and 0x5f07200, are covered
  by their own packets). RE-001-shard-allocate-115 (window
  0x5f117a0) and RE-001-allocate-115 (window 0x5f11c40) both
  record "guard release, called with a stack lock slot in
  cleanup; internals not modelled" and list its internals in
  their unknowns. The RE-002 vendor census registers this exact
  FDE interval (byte-windows id node115-vendor-5f0b5e0) as a
  published-crate rebuild byte match for librocksdb-sys
  0.11.0+8.1.1 `std::unique_lock<rocksdb::SpinMutex>::unlock()`
  — identity and byte equality only; the correspondence with
  the pinned body is literal (the slot is the unique_lock
  layout: device pointer at +0, owns flag at +8; the throw
  code 1 is errc::operation_not_permitted; the cleared byte is
  the mutex lock byte). The merged RE-001 arena packet for
  AllocateAligned 0x605d7b0 is the standing precedent that a
  semantic packet coexists with a vendor window for the same
  interval. No open PR covers this window (checked this cycle:
  699 open PRs swept by title and branch, an address search
  returns zero, and no file in the author's own open PRs names
  the address or a packet for it).

- The window, stated literally. Argument: rdi = a 16-byte lock
  slot (device pointer at +0x00, owns byte at +0x08, padding at
  +0x09..+0x0f, never touched). The body is twelve instructions
  in three arms:

    owns byte == 0:
        push rax; edi = 1; call __throw_system_error via the
        PLT (noreturn — the window never returns, nothing is
        written first)
    owns byte != 0 and device pointer == 0:
        ret, writing nothing — the owns byte stays set
    owns byte != 0 and device pointer != 0:
        byte at the device pointer <- 0   (the lock byte clears)
        owns byte <- 0
        ret

  No value is returned (rax holds the loaded device pointer on
  both normal exits; neither caller reads it). At most two
  bytes are ever written, and the null-device arm is the subtle
  one: ownership is dropped only together with an actual lock
  byte clear, never on its own.

- Why it matters to the callers, stated literally. Both caller
  windows share one cleanup shape: on the pad route they store
  0 to the global lock byte at this + 0x950 directly, then walk
  their two stack lock slots and release each held one through
  this window — shard-allocation at 0x5f11bb3 (slot rsp + 0x40)
  and 0x5f11bc4 (slot rsp + 0x30), allocation at 0x5f120e0
  (slot rsp + 0x30) and 0x5f120f1 (slot rsp + 0x20). Each pad
  tests the slot's owns byte nonzero immediately before its
  call, so from all four sites the window always takes the
  owning arm: the byte behind the slot's device pointer is
  cleared and the slot's owns byte drops. The throw arm is
  therefore unreachable from every mapped caller — it exists
  for the unique_lock contract, not for these pads — and the
  null-device arm is likewise not exercised by the pads, whose
  slots are formed around live lock bytes. What the caller
  packets stated by contract ("the guard-release callee is
  called on the shard-lock slot and/or the global-lock slot per
  the held flags") is now the pinned body above.

- Validation. The model (tools/guard_release_5f0b5e0_115.py)
  passes its 8 tests: the owning arm clears exactly the lock
  byte and the owns byte, the not-owning arm raises the throw
  with code 1 and touches nothing, the null-device arm returns
  with the owns byte still set and zero writes, any nonzero
  owns value releases, a second release raises, and 300
  randomised slot/memory states match the arm table. As an
  additional differential, the window's real 37 bytes were
  executed under Unicorn over 800 randomised slot and lock-byte
  states (the PLT target hooked as a noreturn throw record)
  and matched the model on final slot bytes, lock byte, write
  set and throw behaviour every time (lane-side check; the
  packet checker below does not depend on it). The packet
  checker (verify.py) re-verifies the excerpt, every window
  instruction, the frames block, the census and the model
  tests against the digest-verified binary.
