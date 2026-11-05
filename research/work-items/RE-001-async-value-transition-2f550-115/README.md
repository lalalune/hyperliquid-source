# RE-001: node #115 value transition 0x5a2f550 — a four-state dispatch over a value slot, its helper verdict, and its two resume guards

Task: RE-001 (#115 function map). Bounded question: what does the
whole 273-byte routine at `0x5a2f550` (FDE `0x5a2f550..0x5a2f661`)
do with its environment argument, end to end — how does the state
byte at env +0x90 select among its four arms, what exactly happens
to the binary64 value, the tag byte and the two owned fields on
each arm, and what do the state 1 and state 2 arms do instead of
returning?

- Component: node #115 value transition, one whole function end
  to end, extracted from the digest-verified work binary
  (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  window `0x5a2f550..0x5a2f661` (273 bytes; FDE .eh_frame offset
  0x6fae64, CIE 0x39672c; the FDE carries an LSDA whose call-site
  table is not decoded in this packet).
- Claim status: observation for the window bounds, the jump
  table and its four targets, every field read/write, the
  helper call contract, the counted-field release, the guard
  shims and their message bytes, and the census; inference for
  the readings "resume guard", "completed" and "poisoned" (they
  rest on the two message strings the shims load, quoted below),
  for the assignment of the cleanup pads to call sites (the pads
  are described in address order; assigning them needs the
  undecoded LSDA), and for calling the byte at +0x88 a "tag"
  (it is the byte the helper dispatches on and rewrites);
  unresolved for the items in records.json `not_claimed` (the
  helper's arithmetic, the release routine's internals, what the
  environment and its value denote, the forwarded second
  argument's meaning, states above 3).
- Note on evidence text: the raw disassembly excerpts are
  verbatim objdump output. Instruction mnemonics appearing in
  them are genuine instructions present in the target binary,
  not placeholders; the packet checker re-verifies sampled
  instructions byte-for-byte against a fresh objdump run and
  the raw binary.
- Relationship to earlier work: no merged or open packet takes
  this window as its subject (checked this cycle against the
  563 merged work-items and all 648 open PRs, by address and by
  topic). Two merged packets cite the routine as a callee and
  pin nothing about its body: RE-001-node115-consensus-override-
  descent lists the call at 0x5a794f2 among its subject's direct
  targets with this routine's FDE range only, and RE-001-node115-
  gossip-peer-status-report's caller excerpt contains the call
  at 0x5a61eab. The ten caller FDEs also call the sibling gate
  0x5a52790 (a conditional counted-field release); that routine
  is a separate subject and is not claimed here. This window's
  helper 0x5a2f760 is called from two of the same caller FDEs
  directly (0x5a5fd20, 0x5a86a25); it is cited here by contract
  only.

- The entry, stated literally. Arguments: rdi = environment
  (env), rsi = a second argument the window never reads except
  to forward it to the helper. The byte at env +0x90 (the state)
  indexes a table of signed 32-bit offsets at 0x938f54 relative
  to the table base; there is no bounds check in the window.
  The first four entries land inside the window — state 0 at
  0x5a2f571, state 1 at 0x5a2f60e, state 2 at 0x5a2f601, state 3
  at 0x5a2f597 — and the next table (the helper's own, at
  0x938f64) starts immediately after them. The window itself
  only ever stores the states 1, 2 and 3 (below), and its
  callers pass freshly built or previously transitioned
  environments; behaviour for a state above 3 is not pinned.

- State 0 (the value arm), stated literally. The binary64 at
  env +0x0 is copied to env +0x8. It is then compared against
  0.0 with `ucomisd`: on an ordered equality (this includes
  -0.0) the routine stores state 1 and returns 0, without
  touching env +0x10 or the tag. On any other outcome (nonzero,
  or NaN, which takes the same branch through `jne`/`jp`) the
  value is also stored at env +0x10, the byte at env +0x88 is
  cleared to 0, and the helper arm runs.

- State 3, stated literally. Control enters at 0x5a2f597, the
  middle of the state 0 arm: the copy and the tag clear are
  skipped, and the helper arm runs on whatever the earlier
  transition left at env +0x10 and env +0x88.

- The helper arm, stated literally. r15 is set to env +0x10 and
  the helper 0x5a2f760 (FDE 0x5a2f760..0x5a2fa70, shipped whole
  as helper.txt) is called with rdi = env +0x10 and rsi = this
  routine's own second argument, forwarded unmodified. The
  helper reads the byte at its argument +0x78 (env +0x88) on
  entry and rewrites that byte inside its body (store sites
  0x5a2f9c9, 0x5a2fa47, 0x5a2fa5e); what it computes is not
  modelled here. On its return:
  - true (al nonzero): state 3 is stored and the routine
    returns 1.
  - false: if the tag byte is not 3 at this point, state 1 is
    stored and the routine returns 0, releasing nothing. If
    the tag byte is 3, the counted field is released first:
    the counter cell pointed to by env +0x20 is decremented
    with `lock decq`; when the decrement reaches zero the
    destructor is called through GOT slot 0x64dfdc8
    (relocated target 0x5ce8da0) when the flag byte at
    env +0x18 is nonzero, or through GOT slot 0x64dfdb8
    (relocated target 0x5ce86d0) when it is zero. The field at
    env +0x28 is then released by a call to 0x5a52490 (FDE
    0x5a52490..0x5a52518, shipped whole as release.txt; a shared
    release routine with 82 direct calls binary-wide, cited by
    contract). State 1 is stored and the routine returns 0.

- State 1 (the completion guard arm), stated literally. The
  entry at 0x5a2f60e loads rdi = 0x64b8130 (a global cell whose
  relocated content is 0x4326c1) and calls through GOT slot
  0x64e1368, whose relocated target is the shim 0x1681e60 (FDE
  0x1681e60..0x1681e79, shipped as guard_completion.txt). The
  shim loads the pointer 0x46f2ed and length 0x47 — the bytes
  at that pointer begin with the 35-byte string "`async fn`
  resumed after completion", immediately followed by the
  panicking string below — passes its own argument along in
  rdx, and calls the common noreturn callee 0x1680e80 through
  GOT slot 0x64df6b8. The shim does not return; the block that
  follows it in the window (0x5a2f61b) keeps the exception in
  r14, releases the field at env +0x28 via 0x5a52490, stores
  state 2, and resumes the unwind with `_Unwind_Resume`. The
  natural reading — inference — is that entering the transition
  with state 1 (the state the zero-value and helper-false arms
  finish in) is a resume-after-completion fault, and the
  fault's own cleanup marks the environment poisoned (state 2)
  as it unwinds.

- State 2 (the panicking guard arm), stated literally. The
  entry at 0x5a2f601 first calls through GOT slot 0x64e1360,
  whose relocated target is the shim 0x1681e80 (FDE
  0x1681e80..0x1681e99, shipped as guard_panicking.txt). That
  shim loads the pointer 0x46f310 and length 0x45; the bytes at
  that pointer begin with the 34-byte string "`async fn`
  resumed after panicking". It likewise does not return, and
  its cleanup is the same block as state 1's: release
  env +0x28, store state 2, resume. In the laid-out code the
  state 2 entry falls through into the state 1 entry, so the
  completion shim's call site is shared by both arms' cleanup
  layout; in execution the panicking shim's unwind preempts it.

- The cleanup pads, stated literally, in address order (which
  pad serves which call site is fixed by the undecoded LSDA;
  the assignment in parentheses is the natural reading from
  the values each pad consumes). 0x5a2f61b: keep the exception
  in r14, release env +0x28, continue at 0x5a2f64c (the guard
  calls). 0x5a2f629: call the noreturn cleanup-panic routine
  through GOT slot 0x64df4c0 (relocated target 0x1680cab; its
  message is the 36-byte string "panic in a destructor during
  cleanup") — the double-fault guard for a cleanup that itself
  raises. 0x5a2f62f: keep the exception in r14, store state 2,
  resume (the counted-field destructor calls). 0x5a2f641: keep
  the exception in r14, call 0x5a55e70 (FDE
  0x5a55e70..0x5a55ee2) on the pointer in r15 — the value slot
  env +0x10, set only on the value arms — then continue at
  0x5a2f64c (the helper call). 0x5a2f64c: store state 2, resume
  with the exception in r14. 0x5a2f65b: the cleanup-panic call
  again, closing the window.

- The callers, stated literally. A fresh census (census.py)
  finds exactly 10 direct calls and no tail jumps to this
  routine, and no stored qword or RELATIVE addend holds its
  address. At every site the environment is a field inside the
  caller's own object (offsets +0x10..+0xc18, see callers.tsv)
  and the second argument is a caller value from a register or
  a stack slot; the callers branch on the returned byte (e.g.
  caller.txt: the caller at 0x5a794a0 tests al immediately).
  The ten caller FDEs sit in the consensus and execution caller
  set that other RE-001 packets in this tree document (among
  them the override-descent watcher and the gossip peer-status
  poll); what those callers do with the verdict beyond the
  pinned setups is their own packets' subject, not this one's.
