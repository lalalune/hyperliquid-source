# RE-001-node115-lu-fallback-inner

## Question

Packet #205 asked: decode the fallback's inner route `0x635fb50` — what
does it do with the record C at seg+0x10ec8 and the obj+0x18 reference
(seg+0x29b0), and when does the fallback's gating actually fire?

## Answer (short)

`0x635fb50` is a shared record-C worker, not a fallback-private helper.
Its 7th stack argument selects between two paths: nonzero takes the
lock-wait branch and calls workerB `0x63c1930` with mode 1; zero takes
the main path and calls workerA `0x63c19a0` with mode 0 (when the 6th
argument is nonzero) or mode `2 - [.bss 0x6711ab8]` (when it is zero).
Both paths lock the same record C (mutex C+0x40), maintain the same
owner fields (C+0x28 change count, C+0x30 last owner, C+0x38 update
count, C+0x68 contention flag — the struct #204 characterised), and
pass seg+0x29b0 (= obj+0x18) through to the workers untouched: the
inner route never dereferences it itself. The fallback's gate is
three-way: `[seg+0x10f40] == 0` runs the inner route and then
re-checks from the `.bss` byte; `.bss` byte `0x6711ab8 == 0`, or the
per-segment table byte zero, returns doing nothing; otherwise the
gate tail-jumps to `0x635f4b0` with arg4 = 0.

## Targets

- Inner route: FDE `0x635fb50..0x635fcf2` (1058B).
- Fallback gate: FDE `0x6360610..0x63606ca` (186B; #205 exhibited
  `0x6360610..0x636063a` only — the continuation here is adjacent,
  not overlapping).
- Tail route: FDE `0x635f4b0..0x635f697` (423B, characterised only).
- Workers (not decoded here): `0x63c19a0..0x63c1af4` (340B),
  `0x63c1930..0x63c199d` (109B).

## The inner route, end to end

Signature: `(thread, seg, C, rcx, r8, r9d, stack7)`.

- Prologue (`inner_head.hex`): saves callee-saved registers, maps
  rdi → thread, rsi → seg, rdx → C, rcx/r8/r9d through. The stack
  argument at `[rsp+0x50]` is the 7th argument.
- If stack7 != 0 (`inner_branch.hex`): trylock C+0x40; on failure call
  lock-wait `0x63bf680` (the same helper #204 saw), set flag C+0x68
  = 1, and proceed as if locked. Then the owner-count dance (C+0x38
  += 1; if [C+0x30] != thread, C+0x28 += 1 and [C+0x30] = thread),
  call workerB `0x63c1930(thread, seg+0x29b0, C, rcx, r8, 1)`,
  clear flag, unlock, return 0.
- If stack7 == 0 (main path): trylock C+0x40; on failure set flag
  C+0x68 = 1 and return **1** — the only nonzero return in the
  function, and no current caller observes it (all three callers
  discard eax). On success, the same owner-count dance, then:
  - 6th argument nonzero → mode 0 path (`0x635fc88`): workerA is
    called with r9d = 0.
  - 6th argument zero → mode computation (`inner_call.hex`): r9d =
    `2 - [.bss 0x6711ab8]`, and the `.bss` address is saved for a
    later re-read.
  - WorkerA `0x63c19a0(thread, seg+0x29b0, C, rcx, r8, r9d)` is
    called; its return is tested. If zero: clear flag, unlock,
    return 0 (the re-read `.bss` byte load on this path is discarded
    by the epilogue's `xor eax,eax`). If nonzero: r12 = [C+0x6e8],
    clear flag, unlock, then — only if the re-read `.bss` byte is
    nonzero AND the 6th argument is zero — call the tail route
    `0x635f4b0(thread, seg, C, [C+0x6e8])`, then return 0.

So the inner route uses C for locking, ownership accounting, and one
opaque field (+0x6e8) handed to the tail route; seg+0x29b0 is a
pass-through reference to the workers.

## The fallback gate, completed

Fallback `0x6360610(thread, seg)` (#205's description confirmed and
completed with the table-index math in `gate_cont.hex`):

1. Load [seg+0x10f40]. If zero → cold path: call the inner route
   `(thread, seg, seg+0x10ec8, [seg+0x11cc0], seg+0x29e8, 0,
   stack7=1)`, then loop back to step 2 (not step 1 — the inner
   route runs at most once per fallback invocation).
2. Load `.bss` byte `0x6711ab8`. If zero → return doing nothing.
3. Compute `idx = [seg+0x13450] % [qword at .bss 0x6711aa8]`
   (the segment counter #204 used for the large threshold), read
   the byte at `table_base + 208*idx + 0xac` where table_base is
   the qword at `.bss 0x6711aa0` and 208 = 13*16. If that byte is
   zero → return doing nothing.
4. Otherwise (`gate_tail.hex`): tail-jump to `0x635f4b0(thread,
   seg, seg+0x10ec8, 0)`.

One invocation can therefore run BOTH the inner route (step 1) and
the tail route (step 4). All `.bss` contents (byte, divisor, table
base) are runtime-populated; only addresses and formulas are claimed.

## Census (whole `.text`, byte scan + per-site disassembly check)

- Inner `0x635fb50`: 3 direct E8, 0 E9, 0 LEA, 0 GOT. Sites:
  fallback cold path `0x63606be`, FDE `0x6360ed0` site `0x6361009`,
  FDE `0x6361170` site `0x6361258`. The two non-fallback callers
  pass a DIFFERENT C: seg+0x115c0 (not seg+0x10ec8), rcx =
  [seg+0x11cc0]+0x18, r8 = seg+0x75d8; the `0x6361170` caller passes
  stack7 = 0 and r9d = 1 (main path, mode 0), while the `0x6360ed0`
  caller passes stack7 = a runtime byte (bpl), so its branch is
  runtime-selected.
- Fallback `0x6360610`: 12 direct E8, 0/0/0. Sites in 10 FDEs:
  `0x63607fe` (FDE `0x63606d0`), `0x636130e` (push-small),
  `0x6361806` / `0x636183e` / `0x6361886` (FDE `0x6361320`),
  `0x63628a5` (FDE `0x6362190`), `0x6363acc` (page-owning free),
  `0x6364e3e` (FDE `0x6364880`), `0x63bccb6` (FDE `0x63bcb80`),
  `0x63bd526` (FDE `0x63bd2e0`), `0x63bd6ae` (push-large),
  `0x63bd816` (page sink). The (thread, seg) convention was
  spot-checked at `0x6361806` and `0x63607fe` plus #205's two
  push-wrapper sites. The fallback is a shared primitive, not a
  flush-private helper.
- Tail route `0x635f4b0`: 2 direct E8 (`0x635fc19` inner route,
  `0x6361129` FDE `0x6360ed0`), 1 E9 (`0x6360695` fallback gate),
  0 LEA, 0 GOT.
- WorkerA `0x63c19a0`: 4 E8 (`0x635fbd8` inner, `0x6360f7c` FDE
  `0x6360ed0`, `0x63611ef` FDE `0x6361170`, `0x63c1bfc` FDE
  `0x63c1b00`), 0/0/0.
- WorkerB `0x63c1930`: 2 E8 (`0x635fc71` inner branch,
  `0x63610a4` FDE `0x6360ed0`), 0/0/0.

Note: neither the inner route nor the tail route starts with
`endbr64` (both start with push prologues); only the fallback does.
The verifier asserts the actual first bytes, not an assumed prefix.

## Corrections to earlier packets

- **#205 extended.** Its fallback census (2 sites: the push
  wrappers) grows to 12 sites in 10 FDEs; its inner-route picture
  gains 2 further direct callers that pass C = seg+0x115c0, so C is
  not always seg+0x10ec8; its table-byte description is completed
  with the exact index math (counter % divisor, stride 208, byte
  +0xac). Its guard list, gate-load order, and route targets are
  otherwise confirmed.
- **#205 refined.** The inner route's "worker" split is now
  explicit: stack7 selects workerB (mode 1) vs workerA (mode 0 or
  2 − bss byte), and the tail route's 4th argument differs by
  caller (0 from the gate, [C+0x6e8] from the inner route).
- No other earlier packet is corrected.

## Unresolved (stated, not inferred)

- Full decodes of workers `0x63c19a0` / `0x63c1930` and tail route
  `0x635f4b0` (what the tail route does with arg4, and what the
  workers do with seg+0x29b0, C, and the mode argument).
- Semantic labels of the mode values (0, 1, 2 − bss byte) and of
  the `.bss` byte `0x6711ab8` beyond the exact tests.
- All `.bss` contents (byte, divisor, table base, table bytes);
  the table's entry layout beyond stride 208 and byte +0xac.
- The identities of FDEs `0x6360ed0` / `0x6361170` (the two
  non-fallback inner callers) beyond their call sites.
- C+0x6e8's purpose beyond being the tail route's 4th argument.

## Next question

Decode the tail route `0x635f4b0` end to end: what does it do with
(thread, seg, C, arg4), and what distinguishes its two call shapes
(arg4 = 0 from the gate vs arg4 = [C+0x6e8] from the inner route)?
Behind it, still open: the workers `0x63c19a0` / `0x63c1930`, the
two runtime method pointees ([seg+0x29d0] / [seg+0x11cf0] writers),
the drain helper `0x51e8720`, the field-drop callees `0x5a50a10` /
`0x5a4d200`, and #200's delegates `0x51f3e20` / `0x57ec1b0` and
unwind callee `0x1680cab`.

## Verification

- Static verifier `tools/node115_lu_fallback_inner.py`: exit 0
- Unit tests `tests/test_node115_lu_fallback_inner.py`: 8/8 pass
- MANIFEST: 15/15 entries match
- `make doctor`: analysis_ready true
- `make verify`: exit 0
- `make catalogue-check`: exit 0
- `make test`: 77 files attempted, 1 failed — the single failure is
  the pre-existing test_node115_catalogue Errno 18
  cross-device-link error; this packet's file [36/77] passes 8/8
