# RE-002: the bit-9 F2 stream traced — the SSSE3 form of the ChaCha block function (four blocks in parallel, feed-forward, counter advanced by 4), selected by the family's only tail jump from a CPU-feature dispatcher whose clear arm is the same computation in SSE2 form

- Component: RE-002 build provenance / runtime-cache provenance —
  the operation behind the two-sequence arm family of the cache
  readback (PRs #2496, #2616, #2650, #2694, #2739).
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Question: PR #2616 pinned the set arms of the 92 bit-9 cache
  consumers and stopped at each target's entry-level identity;
  PRs #2650, #2694 and #2739 traced F1, F4 and F3 — all one
  lowercase hex encoder at three shapes. PR #2739 left as its
  next question, verbatim: "trace the F2 tail-jump body at
  `0x5bba120` — at 1,758 bytes with a prologue that loads two
  32-byte halves of its input record, it does not have the
  encoder's shape at all, so the question is what operation
  the last bit-9 set arm actually selects, and where its tail
  jump lands."

## Answer

**The F2 set arm does not select an encoder at all. It selects
the ChaCha block function in its SSSE3 form: four blocks
worked in parallel in transposed form, with feed-forward, and
the state record's 64-bit counter advanced by 4.** Traced in
full at its sole placement `0x5bba120..0x5bba7fe` (1,758 bytes,
340 instructions, SHA-256
`e787f6af5ff38fbe899147dac51fec44e1d6887fa0a5ef131bd0a528c38f0245`):

- the constants name the operation. The body's round constants
  are the 16-byte ASCII string `"expand 32-byte k"` at
  `0x4519c0` — the ChaCha sigma row — and its exact per-word
  double at `0x456c50` (`0xc2e0f0ca, 0x6640c8dc, 0xf2c45a64,
  0xd640cae8` = 2×sigma), which the zero-round path loads.
  The two `pshufb` masks are the SSSE3 byte rotations
  (`0x4531c0`: rotate-by-8 pattern `[3,0,1,2, …]`;
  `0x452ec0`: the swap pattern `[14,15,12,13, …]`).
- the round loop (head `0x5bba230`, back edge `jne` at
  `0x5bba693` after `dec esi` at `0x5bba691`, 217 instructions)
  is the ChaCha quarter-round network on 32-bit words:
  `paddd`/`pxor` with rotations 16 (`pshuflw`/`pshufhw 0xb1`
  word swaps, 8+8), 12 (`psrld 0x14` / `pslld 0xc`, 8+8),
  8 (`pshufb`, 16 in the loop) and 7 (`psrld 0x19` /
  `pslld 0x7`, 8+8), with `pshufd` lane rotations
  `0x39`/`0x4e`/`0x93` for the diagonal rounds. One loop
  iteration runs two double rounds; `esi` is the iteration
  count, so the caller chooses the round count.
- the entry (`sub rsp,0x38`, no calls anywhere in the body)
  reads bytes `0x00..0x30` of the record at `rdi` — three
  16-byte rows at `[rdi]`, `[rdi+0x10]`, `[rdi+0x20]`; bytes
  `0x30..` are never read — and builds four counter rows from
  the 64-bit counter word at `[rdi+0x20]` (+0/+1/+2/+3, at
  `0x5bba131`/`0x5bba167`/`0x5bba18f`, carry into the high
  dword via `shr 0x20`): four blocks, one counter step apart.
- the epilogue (merge `0x5bba6fd`) is the ChaCha feed-forward:
  worked rows are added to the entry-saved initial rows — the
  constant rows receive their sigma add just after the loop
  (load at `0x5bba699`, adds `0x5bba6a1..0x5bba6b0`) — and
  stored as 16 vector stores covering 256 bytes at `rdx`
  (four 64-byte blocks); the counter row is rebuilt with the
  counter advanced by 4 (`add rax,0x4` at `0x5bba6fd`) and
  stored back at `[rdi+0x20]` (`0x5bba72f`). The body ends in
  `ret`; it has exactly three branches, all internal.
- with `esi == 0` (`test esi,esi` at `0x5bba1bc`, `je` at
  `0x5bba1e2`) no round runs and the output is exactly
  initial + initial: the constant rows come from the
  precomputed doubled sigma and the epilogue adds double the
  other rows. The full 256 bytes are still written and the
  counter still advances by 4.

**Where the tail jump lands, and what selects it.** The one
selecting body, `0x5bba800..0x5bbb030` (2,096 bytes, SHA-256
`22a8929e34ff5d1e13f8829269ad2d630b597b9c34981312fddbc163866be0e0`),
is a CPU-feature dispatcher — the family's only
`tailjmp`/`inbody` sequence (1 of 104). It loads the cached
feature word through slot `0x64dfa60` (refreshing it through
slot `0x64dfa68` when a test finds it uninitialised; four
refresh call sites), and walks its tests in a fixed order —
sign bit (`0x5bba823`, exit to `0x5bbb630`), `0x4000`
(`0x5bba835`, exit to `0x5bbb030`), `0x400` (`0x5bba84c`,
exit to `0x5bb9a60`) — before testing bit 9: `test eax,0x200`
at `0x5bba863` (and at `0x5bbb013` on the refresh-retry path).
Bit 9 is cpuid leaf 1 ecx bit 9 (SSSE3) per the #2616 driver
table. When it is set, the set-arm block at `0x5bbb01e`
unwinds the dispatcher frame (`add rsp,0xa8`, four pops) and
tail-jumps at `0x5bbb02b` **into `0x5bba120`, the F2 body
itself** — entered with the dispatcher's own caller arguments
(`rdi`, `esi`, `rdx`), so the F2 body's `ret` returns straight
to that caller. A validated census of every direct E8/E9
transfer in `.text` finds exactly this one jump to the body,
and no call.

**The dispatcher's clear arm is the same operation in its
SSE2 form** — the analogue of the scalar form for this family.
When bit 9 is clear, control falls through at `0x5bba86e` into
the dispatcher's inline copy of the computation: the clear
region (1,753 bytes over blocks `0x5bba86e, 0x5bba91e,
0x5bba970, 0x5bbadfd, 0x5bbae21, 0x5bbae63`, SHA-256
`ab8a5c9f0fe3fc7e313f849d087cbad2b3dd3b84aa1d8d0fb5dd155925b17c76`,
byte-verified against the #2616 pin) references the same
sigma (2 refs) and doubled sigma (1), builds the same three
counter-variant `lea`s, runs the same loop shape (rotations
16/12/7 counted 24/8/8) and shares the epilogue (counter
`+= 4` once, one `[rdi+0x20]` write-back, 16 output stores)
— with **zero `pshufb`**: the 8-rotation is done with
`psrld 0x18` / `pslld 0x8` shift pairs (8), which is exactly
the SSSE3 gap bit 9 tests. So the bit-9 test again chooses
between two forms of one operation — here not scalar vs
vector, but SSE2 vs SSSE3.

**The dispatcher itself has no direct caller.** The same
census finds no direct E8/E9 transfer to `0x5bba800` at all:
the body is entered indirectly only (the census covers
direct transfers only; which slot or table names it is
outside this question).

## Exact scope

| Role | Count |
| --- | ---: |
| tip target bodies re-verified against #2616 pins (FDE, size, SHA-256, insns, normalised stream) | 14 of 14 |
| bit-9 consumer bodies re-verified against #2616 pins (SHA-256) | 92 of 92 |
| F2 placements traced | 1 (`0x5bba120`, 1 sequence) |
| F2 selection sequences classified | 1 (1 body) |
| clear regions byte-hash-verified against #2616 region pins | 1 |
| clear verdicts | 1 same-operation-SSE2-form, 0 other |
| direct transfers to the traced body validated | 0 calls, 1 jump (the set-arm tail jump) |
| direct transfers to the dispatcher validated | 0 calls, 0 jumps |

## Stage 1 — pin re-verification

The producer authenticates the whole capture (size + SHA-256)
before any analysis, then re-derives from the binary alone: FDE
ranges via `readelf` (135,313 FDEs), every target and consumer
body hash through the section table, every target's instruction
count by fresh `objdump` disassembly, and every target's
normalised instruction stream by #2616's normalisation
definition. Any mismatch fails the producer closed. All 14
targets and all 92 consumers match their merged pins, and the
F2 placement hashes to #2616's pinned normalised-stream digest
`c1ea182b6e4281bbbcc48be58904200776445b0b614e24b7233f0edba8c3bd36`
— a distinct stream from every F1/F3/F4 placement, so F2 is a
distinct body, not a clone of any encoder placement.

## Stage 2 — the trace of 0x5bba120

- Entry and transpose (`0x5bba120..0x5bba1e2`, up to the gate):
  the three record rows are loaded, the counter word is taken
  into `rax`, the +1/+2/+3 counter rows are built (each
  `lea`/`movd`/`shr 0x20` group ORs the counter's high dword
  and the record's trailing words into the row), the initial
  rows are saved on the 0x38-byte frame and in the red zone
  for the feed-forward adds, and `test esi,esi` gates the
  zero-round path. The body's only external references are
  the four `.rodata` constants (`0x4519c0`, `0x452ec0`,
  `0x4531c0`, `0x456c50`), read through the section table;
  there are no callees.
- Round loop (`0x5bba230..0x5bba693`, 217 instructions): two
  double rounds per iteration — column quarter rounds then
  diagonal quarter rounds, the diagonalisation done with
  `pshufd` `0x39`/`0x4e`/`0x93` lane rotations and the second
  double round's shuffle taken through the `0x452ec0` mask.
  Rotation census in `records.json` (`trace.round_loop`):
  32 `paddd`, 32 `pxor`, 16 `pshufb`, 8 each of the
  16/12/7 rotation pairs. `dec esi` at `0x5bba691` and the
  `jne` back edge at `0x5bba693` close the loop.
- Post-loop and zero-round paths: both join the epilogue at
  `0x5bba6fd` — the loop path via the `jmp` at `0x5bba6ba`
  after the sigma adds, the zero-round path by falling
  through from `0x5bba6bc` with the doubled sigma loaded.
- Epilogue (`0x5bba6fd..0x5bba7fd`): 12 `paddd` feed-forward
  adds in this span (the four constant-row adds happened
  before the merge), the counter write-back, 16 output
  stores, `add rsp,0x38`, `ret`.

## Stage 3 — the dispatcher and its clear region

The producer rebuilds the dispatcher's basic blocks (the
#2616 construction), reassembles the clear region's bytes
from the blocks #2616 pinned, and requires the region's
SHA-256 and byte count to equal the pinned `region_sha256` /
`bytes` — the region analysed is therefore exactly the region
#2616 measured, re-derived from the binary. Classification
counts (in `records.json`): sigma references, doubled-sigma
references, `pshufb` count, the 16/12/8/7 rotation counts,
counter-variant `lea`s, output stores, counter write-backs
and counter advances. Verdict rule, fixed before the run:
same-operation-SSE2-form iff the region references both
sigma constants, builds the three counter variants, has a
shift-based 8-rotation with no `pshufb` at all, and shares
the epilogue shape. The dispatcher's own structure — feature
slot, refresh calls, test order and all four exits — is
pinned instruction by instruction in `dispatcher_analysis`
(`records.json` under `dispatcher`; `dispatcher.objdump.txt`
retains the body dump, `clear_regions.objdump.txt` the
region's code).

## Stage 4 — direct transfers

The producer censuses every E8/E9 byte hit in `.text` whose
relative target is the traced body, and separately every hit
whose target is the dispatcher body, validating each hit
against the disassembly of its containing FDE (a hit must be
an instruction boundary transferring to the target). The
validated result for the F2 body is exactly one jump — the
set-arm tail jump `0x5bbb02b` named by the #2616 sequence
record — and no call; for the dispatcher it is empty, so the
dispatcher is reached indirectly only.

## Explicit boundary and next question

What is **not** established: the operations of the
dispatcher's three other exits — the bodies at `0x5bbb030`
(1,522 bytes), `0x5bb9a60` (442 bytes) and `0x5bbb630`
(868 bytes), selected by the `0x4000`, `0x400` and sign-bit
tests — whose addresses are pinned here but whose operations
are not traced; which indirect slot or table names the
dispatcher (it has no direct caller); what round-count
values (`esi`) any caller passes, and therefore which ChaCha
variant (8/12/20) any given invocation computes; who consumes
the 256 output bytes downstream; and any runtime values.

Next question: trace the dispatcher's `0x4000`-exit body at
`0x5bbb030..0x5bbb62a` — the next feature exit in test order
after bit 9 — and name its operation: whether it is the same
ChaCha block function at a wider vector form, and how its
counter/output contract compares to the F2 body's.

## Reproduce and validation

From repository root with the materialized pinned capture and
native GNU tools on PATH:

```sh
python3 -B tools/bit9_f2_trace_static.py --output research/work-items/RE-002-node115-bit9-f2-trace
python3 -B -m unittest discover -s tests -p test_bit9_f2_trace_static.py -v
(cd research/work-items/RE-002-node115-bit9-f2-trace && sha256sum -c MANIFEST.sha256)
```

The whole capture is authenticated before analysis, output or
native calls. Objdump/readelf receive a private byte-identical
snapshot; the snapshot path is replaced with
`<authenticated-node115>` in retained text. Wrong-release,
truncated and same-size modified public inputs are rejected
before output creation.

Focused controls alter, in an in-memory copy below the digest
gate: one byte inside the traced body `0x5bba120` and one
inside another set-arm target `0x5bddee0` (the re-derived body
hashes no longer match the #2616 pins), one byte of the sigma
constant at `0x4519c0` (the traced constants no longer name
the operation), and one byte inside the dispatcher's clear
region (the re-derived region hash no longer matches its
pin). These are checks of the named obligations — the pin
re-verification, the constant identity, and the region
pinning — not target execution.

No captured executable/emulator, live chain/wallet/signing action
or network access is performed. No hosted-CI result or
whole-component completion is claimed.
