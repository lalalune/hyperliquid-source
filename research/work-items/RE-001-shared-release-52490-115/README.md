# RE-001: node #115 shared release routine 0x5a52490

Task RE-001. Bounded question: what does the whole 136-byte
routine at `0x5a52490` (FDE `0x5a52490..0x5a52518`) do with its
single cell argument, end to end — which fields it reads, in
what order it releases them, what it calls, and what happens
when one of those calls raises?

Three packets already filed against this tree cite this
routine without pinning it: the transition packet at
`0x5a2f550` (PR #3309) and the duration-step packet at
`0x5a2f760` (PR #3318) call it to release a field, and the
sibling-gate packet at `0x5a52790` (PR #3316) names it "the
shared release routine" and tail-jumps to it. Two merged
packets (consensus-override-descent, gossip-peer-status-report)
list it as a direct call target in their records. No open or
merged packet takes its body as its subject; that is the gap
this packet closes. The four-line summary:

- Touching action: 82 direct calls and 14 tail jumps from 45
  caller FDEs across the node's async region release a cell
  through this one routine.
- Basis: the digest-verified binary itself — FDE range, the
  LSDA call-site table decoded from `.eh_frame`, four slot
  relocations, and the 36-byte panic string read raw.
- Loss if misread: every consumer analysis that treats the
  release as "free the field" misses the state-2 early return,
  the discarded-result first call, and the destructor/callback
  ordering, and any unwind through it is misattributed.
- Nearest existing work: PR #3316 by repro case (question)
  answers what the gate does before it tail-jumps here; it
  does not decode this routine. Re-checked against all 663
  open PR titles/bodies and all 563 merged work-items.

## Answer, pinned to the target binary

The argument is a pointer in `rdi` to a cell laid out as:

| offset | what the routine does with it |
|---|---|
| +0x00 | dword state. Compared against 2 first; its low byte later selects a destructor. |
| +0x08 | pointer to a refcount qword; the qword is `lock dec`-remented. |
| +0x10..+0x2f | never read or written by this routine's own instructions. |
| +0x30 | callback table pointer; tested for zero. |
| +0x38 | callback data; loaded into `rdi` for the callback. |

In order:

1. **Released-state early return.** `cmpl $0x2,(%rdi)` at
   `0x5a52494`: if the state dword equals 2, the routine
   returns at once. Nothing else is read — no first call, no
   decrement, no callback.
2. **First callee.** An indirect call at `0x5a5249c` through
   slot `0x64dfe40` (RELATIVE addend `0x5ceafd0`, FDE
   `0x5ceafd0..0x5ceb1a4`) with `rdi` = the cell itself. Its
   return value is discarded; the body is not modelled.
3. **Pair release.** `rax = [+0x08]`, then `lock decq (%rax)`
   at `0x5a524ae`. Only when the decrement reaches 0 is a
   destructor called with `rdi = cell + 8`, chosen by the
   byte at +0x00: nonzero selects slot `0x64dfdc8` (addend
   `0x5ce8da0`, 801-byte FDE), zero selects slot `0x64dfdb8`
   (addend `0x5ce86d0`, 389-byte FDE). Both destructor bodies
   are cited only. The standalone helper at `0x5a4f0e0`
   (43 bytes, shipped whole as `cleanup.txt`) is this same
   step as a separate routine: same decrement, same
   byte-selected destructor, reached by tail jump.
4. **Callback.** `rax = [+0x30]`; if it is 0 the routine
   returns. Otherwise it pops its saved registers and tail
   jumps `jmp *0x18(%rax)` at `0x5a524df` with
   `rdi = [+0x38]`, so the callback returns directly to this
   routine's caller. (The table-plus-`+0x18` shape matches
   the drop slot of a raw-waker vtable; the packet pins the
   offsets, the null test and the argument only, and does
   not claim that identity.)

## Unwind behaviour (from the LSDA, not inferred)

The routine's LSDA call-site table decodes to five entries
(verify.py re-decodes it from the binary on every run):

| call-site range | covers | landing pad |
|---|---|---|
| `0x5a52499..0x5a524a2` | the first-callee call `0x5a5249c` | `0x5a524ef` |
| `0x5a524b4..0x5a524cb` | both destructor calls `0x5a524b4`, `0x5a524c5` | `0x5a524ea` |
| `0x5a524cb..0x5a524f2` | the callback test/tail region, pad prologues | none |
| `0x5a524f2..0x5a5250a` | the pads' own calls `0x5a524f5`, `0x5a52507` | `0x5a52512` (action 1) |
| `0x5a5250a..0x5a52518` | `_Unwind_Resume` call, final shim call | none |

- Pad `0x5a524ef` (first callee raised): saves the exception,
  runs the pair release through the helper `0x5a4f0e0`, then
  performs step 4 as a **call** (`call *0x18(%rax)` at
  `0x5a52507`, when the table is present), then calls
  `_Unwind_Resume` (PLT `0x63f0a50`).
- Pad `0x5a524ea` (a destructor raised): performs only step
  4 as a call, then `_Unwind_Resume`. The pair release is
  **not** run a second time — the decrement happens exactly
  once per release on every path.
- Pad `0x5a52512` (a call inside a cleanup pad raised): this
  address is the routine's final instruction, an indirect
  call through slot `0x64df4c0` (addend `0x1680cab`). The
  20-byte shim there (shipped whole as `panic_shim.txt`)
  loads the message at `0x46e9bd` with length `0x24` — the
  raw bytes are "panic in a destructor during cleanup",
  checked byte-for-byte by verify.py — and calls through
  slot `0x64e1f28` (addend `0x1680e40`). The same instruction
  also sits after the `_Unwind_Resume` call, which never
  returns, so its only live entry is as this landing pad.

## Transfers

The routine's own transfers are exactly 2 direct calls (the
pair helper at `0x5a524f5`, `_Unwind_Resume` at `0x5a5250d`),
0 direct tail jumps out, 5 indirect calls (`0x5a5249c`,
`0x5a524b4`, `0x5a524c5`, `0x5a52507`, `0x5a52512`) and 1
indirect tail jump (`0x5a524df`). Its internal direct jumps
all land inside the routine. The byte at `0x5a52518` is the
first byte of the next FDE, not part of this routine.

## Consumers (site-only)

The census finds exactly 96 transfer sites — 82 direct calls
and 14 tail jumps — in 45 distinct caller FDEs, all in the
`0x5a2xxxx`–`0x5abxxxx` region; no stored qwords and no
RELATIVE addend name the routine address itself (full list in
`callers.tsv`). The `rdi` setup is pinned for six sites:

- `0x5a2f5e8` and its cleanup-pad twin `0x5a2f622`, inside
  the transition `0x5a2f550..0x5a2f661` (#3309): both are
  preceded by `lea 0x28(%rbx),%rdi` — the cell is the field
  at owner +0x28.
- `0x5a527ec` (tail jump) and `0x5a527fb` (call, cleanup
  pad), inside the sibling gate `0x5a52790..0x5a5280e`
  (#3316): `rdi` = gate owner + 0x28, the same field.
- `0x5a6d2a3` and its cleanup-pad twin `0x5a6d342`, inside
  `0x5a6d200..0x5a6d385`: `lea 0xa8(%rbx),%rdi` — the cell
  sits at owner +0xa8 there.

For the remaining 90 sites the setup is recorded as not
pinned; the sites themselves are objdump-confirmed by
census.py on every verify run.

## Relation to existing packets

- PR #3309 (transition `0x5a2f550`) and PR #3318 (duration
  step `0x5a2f760`, which calls this routine at `0x5a2f9c2`
  and `0x5a2fa33`) describe the cell only as "the +0x28
  field" being released; PR #3316 (sibling gate) names this
  routine as its tail-jump target. This packet is the body
  those three cite.
- The two destructor slots (`0x64dfdc8`, `0x64dfdb8`) are
  shared with other cells in this region — RE-005
  gate-checkers, for example, pins the same pair chosen by a
  byte of a different object. Sharing the slots does not
  make those packets about this routine, and this packet
  does not re-pin the destructors.

## Honest limits

- Callee bodies are out of scope: the first callee
  `0x5ceafd0`, both destructors, the callback, and the panic
  entry `0x1680e40` are cited by address, FDE and slot only.
- What the cell denotes at a higher level, who writes its
  fields, and which state values besides 2 occur in practice
  are not claimed; the model refuses a null +0x08 pointer
  exactly where the binary would fault.
- No Unicorn differential test: the model tests in
  `tests/test_shared_release_52490_115.py` check the pinned
  decision table, including the three landing pads and the
  decrement-exactly-once invariant, against hand-computed
  expectations only.
