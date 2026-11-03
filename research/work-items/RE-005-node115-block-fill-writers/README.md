# RE-005 node 115: who fills the descriptor blocks and the decoder's +0x28

## Question

The input-writers packet (`RE-005-node115-input-writers`) pinned the
four top dispatchers' direct callers and showed the derivation inputs
are never written inside them: they arrive as the incoming contents of
descriptor blocks inside the callers' context structs (a side) and of
a shared arena (b side). It left two questions open:

1. Who fills the caller context structs' descriptor blocks — block
   offsets: bulk selector `+0x178`, bulk incoming limit `+0x1b0`, twin
   source pointer `+0x8`, twin sibling `+0x108`, twin incoming limit
   `+0x110` — and the b-side arena fields the dispatchers read
   (object-relative `+0xc08`/`+0xc40`/`+0x958`/`+0xa58`/`+0xa60`;
   arena offsets `+0x2900`/`+0x2a00`/`+0x2a08`, `+0xeb8`/`+0xef0`,
   `+0xc18`/`+0xd18`/`+0xd20`)?
2. What writes the nested decoder `0x2ce1730` result's `+0x28` field,
   which the twin-a stage `0x2e466b0` forwards at its sole `+0x28`
   store (`0x2e46968`, loaded at `0x2e467a8`)?

## Method

Static trace only, against the authenticated node 115 binary (SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
Twelve functions are pinned by exact FDE extent, body SHA-256 and
per-instruction byte pins: the input-writers packet's two bulk-a
callers (`0x2ad7140..0x2adce3a`, `0x2cc1120..0x2cc971b`, re-pinned
byte-identically), their four direct callers, the five level-2 phase
functions above them, and the nested decoder
`0x2ce1730..0x2ce198a`. The two small bodies (the decoder, 602 bytes;
the phase function `0x2ae0920..0x2ae135b`, 2,619 bytes) retain full
objdump exports; the rest are retained as hash plus pins. A
direct-access census over fresh objdump text, a binary-wide E8/E9
caller census, and a relocation/rip-relative census for the b-side
boundary are re-derived on every run of
`tools/block_fill_writers_static.py`. No captured code was executed.

## Findings — question 1

Every traced caller is itself a phase function embedded in a larger
pipeline record, and the pattern from the packet below repeats at
every level: the record arrives by pointer (entry `rsi`; in
`0x2b41b70` dereferenced once from `[rsi]`), an embedded sub-record is
passed down, and only the sub-record's **head fields** are initialised
at the call — the bulk struct at outer record `+0xf8` / `+0x68`, the
twin structs at bulk struct `+0x70`, at array elements of stride
`0xf60` plus `0x1d0`, at phase record `+0x10`, at bulk-a-2 records
`+0x128` and `+0x220`.

A direct-access census of the target offsets — mapped through every
embedding, via the record register and the pinned alias registers, in
all twelve bodies — finds:

- **Bulk selector and bulk incoming limit: no access anywhere.** No
  store to, and no read of, the mapped offsets exists in any pinned
  body at any embedding.
- **Twin sibling and twin incoming limit: no access anywhere, with one
  intra-record exception.** Inside caller bulk a 1, a record-shaping
  arm (spanning `0x2ad83a1..0x2ad851f`) stores the record's own
  `[struct +0x60]` qword into the twin sibling offset (`0x2ad8459`,
  read back at `0x2ad8521`) and copies `0xa0` bytes from
  `[struct +0x120]` over the twin limit offset (copy call at
  `0x2ad84cb`, read back at `0x2ad84ed`). Both sources are inherited
  record fields (`[struct +0x60]` is itself stored in the twin-call
  arm from `[struct +0x50]`; `[struct +0x120]` has no direct store in
  the body), and the shaping arm is a different jump-table arm from
  the twin call at `0x2adacc4` — a direct-edge block graph reaches
  neither arm from the other — so the exception reshapes a record
  from its own incoming contents; it originates no input. Caller bulk
  a 2's analogous shaping copy (`0x2cc57cb`, `0xa0` bytes from
  `[r15+0x1d8]` to `[r15+0x280]`) covers no twin target offset in its
  frame.
- **Twin source pointer: no access in any pinned body.** Within the
  traced window its only writer remains the twin caller itself on its
  first entry arm (input-writers packet); on the other arm the value
  is the record's incoming contents.
- **B side: the trace stops at an indirect boundary.** The shared
  b-side caller `0x5a82670` has no direct call site and no tail call
  anywhere in the binary. Its address occurs exactly once in the
  binary's data — as the addend of the `R_X86_64_RELATIVE` relocation
  at slot `0x64b91c0` in `.data.rel.ro`, among neighbouring
  phase-function pointers (`0x5a5c580`, `0x5a820d0`, `0x5a5c610`, and
  the repeated default handler `0x43bce4`) — and no instruction in
  `.text` references that slot rip-relatively. It is invoked through
  a table walk, so the arena reaches it from a caller that is not
  statically attributable, and no traced body writes any arena input
  offset.

So the first writer of the descriptor-block fields and the arena
fields sits **above the traced window and, on the b side, above an
indirect boundary**: it is the producer of the pipeline records
themselves. The level-3 caller sets of the five level-2 functions are
censused in `records.json` (`call_census`); their bodies are the next
rung, not pinned here.

## Findings — question 2

The chain bottoms out: the nested decoder writes its own result's
`+0x28`. The decoder `0x2ce1730..0x2ce198a` (602 bytes) takes its
result pointer in `rdi` and its state pointer in `rsi`, and reads up
to five u64 values through the reader helper `0x2cd7ac0` (call sites
`0x2ce1749`, `0x2ce1768`, `0x2ce1788`, `0x2ce17a8`, and `0x2ce1843` on
one arm). Each read's value qword is captured only when the read
record's tag byte equals `0x12`: read 1 → `r15`, read 2 → `r12`,
read 3 → `r13`, read 4 → `rbp` (at `0x2ce17bb`).

- The result's `+0x28` is stored exactly once, at **`0x2ce191e`** in
  the success store block (`0x2ce1901..0x2ce1922`), from `rbp`: **the
  fourth decoded value**. The same block fills `+0x0`/`+0x8` from the
  mode-byte pair, `+0x10` = read 1, `+0x18` = read 2, `+0x20` =
  read 3; the success tag at `+0x0` is 0 or 1, never 2.
- Every failure arm — a read tag other than `0x12`, a bad or
  exhausted mode byte — stores some subset of the remaining fields
  and the tag 2 (at `0x2ce1971`) or the error tag byte, and **none of
  them stores `+0x28`**: the slot keeps its previous contents. That
  is exactly the distinction the stage relies on when it forwards
  `+0x28` only on the tag ≠ 2 arm.

## Boundaries and next question

The direct-access census covers the record register and the pinned
alias registers of the twelve bodies; whole-record copies move bytes
without naming fields, and copy destinations were reviewed in the
level-0/1 bodies (stack buffers, register-held pointers, non-target
record ranges, apart from the two shaping copies recorded above).
Next questions: who produces the pipeline records the level-3
functions operate on (the first writer of every descriptor-block
field traced so far), which code walks the `.data.rel.ro` handler
table containing slot `0x64b91c0` (the b-side caller's driver), and
which producer writes the decoder's state buffer (state `+0x10`
cursor, `+0x18` remaining, `+0x20` index) whose fourth decoded value
the stage result's `+0x28` ultimately carries.

## Files

- `records.json` — machine-readable owners, pins, censuses and
  findings (regenerated by `tools/block_fill_writers_static.py
  --generate`).
- `frames.txt` — `readelf -wf` FDE lines for the twelve pinned
  functions.
- `*.objdump.txt` — full disassembly exports of the two small bodies.
- `MANIFEST.sha256` — hashes of the retained files.
- Tests: `tests/test_block_fill_writers_static.py`.
