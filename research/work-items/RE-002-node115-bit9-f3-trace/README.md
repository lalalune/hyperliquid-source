# RE-002: the bit-9 F3 stream traced — F1's full-length lowercase hex encoder with reworked remainder bookkeeping — and both selectors' clear regions are its scalar form

- Component: RE-002 build provenance / runtime-cache provenance —
  the operation behind the two-sequence arm family of the cache
  readback (PRs #2496, #2616, #2650, #2694).
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Question: PR #2616 pinned the set arms of the 92 bit-9 cache
  consumers and stopped at each target's entry-level identity;
  PR #2650 traced the largest stream, F1, as a lowercase hex
  encoder; PR #2694 traced F4 as the same encoder in a bounded
  variant and left as its next question, verbatim: "trace the F3
  stream at `0x5bd6e90` — it shares F1's arbitrary-length
  prologue but handles its remainder differently, so the
  question is which part of the encoder, if any, it reuses, and
  whether its 2 selectors' clear regions are again the scalar
  form."

## Answer

**F3 reuses the whole encoder. It is the same operation as
F1 — a lowercase hexadecimal encoder — in its full
arbitrary-length form, with only the remainder bookkeeping
reworked.** Traced in full at its sole placement
`0x5bd6e90..0x5bd6fcf` (319 bytes, 78 instructions, SHA-256
`d1a5f0e4fa3b802ae08a3b37fdec93f962e5606eb6f890febbaefac8dcc907e5`):
it takes an input pointer in `rdi`, a byte length in `rsi` and
an output pointer in `rdx`, contains no call, and writes two
characters per input byte, `out[2i] = table[in[i] >> 4]`,
`out[2i+1] = table[in[i] & 0xf]`, where `table` is the same
16-byte ASCII string `0123456789abcdef` at `0x455d40` in
`.rodata` that F1 reads, next to the same 16×`0x0f` nibble mask
at `0x4503b0`. Its entry mask is F1's: the vector byte count is
`length & 0x7ffffffffffffff0`, so the vector loop covers all
but the last 15 bytes and the conversion is exact for **every**
length — nothing like F4's `length & 0x3f` truncation. Its main
loop is F1's SSSE3 loop at the same size (17 instructions, two
`pshufb`, 16 input bytes → 32 stored bytes per iteration),
with `r8` as the counter where F1 uses `rcx`.

What differs is only how the remainder is handled:

- the remainder `length & 0xf` is computed **at entry**, into
  `ecx`, before the vector loop (F1 derives its remainder
  inside its tail);
- the scalar tail's pairs loop addresses its stores through a
  pointer built as `(2 · vector bytes) + output + 3`, so the
  four stores of each two-byte iteration land at displacements
  −3..0 — plain sequential output offsets once the +3 is
  folded in;
- a remainder of exactly 1 skips the pairs loop entirely:
  `ecx` (the final byte's index) is zeroed and control jumps
  straight into the final-byte code, which the odd-remainder
  path also reaches after its pairs loop.

**Both clear regions of the F3 selectors are the scalar form
of that same operation** (2 of 2, byte-hash-verified against
#2616's pins, both loop form, both hi-nibble first):

- consumer `0x5bd4500..0x5bd45d5` (set length constant 32): its
  clear region is a 2-bytes-per-iteration loop over the same
  32 bytes (`cmp rax,0x21`, step 2, from 1), same table;
- consumer `0x5bd4bb0..0x5bd4d24` (set length fully runtime):
  its clear region is a pairs loop over `length & ~1` plus the
  final odd byte, same table.

**Direct callers: exactly two, and they are the two set arms.**
A validated census of every direct E8/E9 transfer in `.text`
finds the call sites `0x5bd45b4` and `0x5bd4c3f` — precisely the
two selectors' set-arm calls — and no direct jump to the body
at all. What the consumers do with the text:

- `0x5bd4500` frames the 32-byte value it converts as text:
  a `"0x"` prefix word (`0x7830`) sits at `rsp+0x6`, the
  encoder writes at `rsp+0x8`, and the framed 66-byte text is
  handed to an indirect call `QWORD PTR [rax+0x18]` with
  `edx = 0x42` — a virtual-method hand-off, after which the
  body returns;
- `0x5bd4bb0` is the general form: it allocates `2 · length`
  through the indirect slot `0x64df480`, encodes into that
  buffer, and stores a three-word record at its out argument —
  `[out] = 2 · length`, `[out+0x8] = buffer`,
  `[out+0x10] = 2 · length` — returning the record pointer.
  The encoded text becomes a length/pointer/capacity string
  owned by its caller.

So for these consumers the two arms are again one operation at
two speeds: the bit-9 test chooses between the shared SSSE3
encoder and the consumer's own scalar encoder of the identical
byte string.

## Exact scope

| Role | Count |
| --- | ---: |
| tip target bodies re-verified against #2616 pins (FDE, size, SHA-256, insns, normalised stream) | 14 of 14 |
| bit-9 consumer bodies re-verified against #2616 pins (SHA-256) | 92 of 92 |
| F3 placements traced | 1 (`0x5bd6e90`, 2 sequences) |
| F3 selection sequences classified | 2 (2 bodies) |
| clear regions byte-hash-verified against #2616 region pins | 2 |
| clear verdicts | 2 scalar-hex-table, 0 empty, 0 other |
| direct transfers to the traced body validated | 2 calls, 0 jumps |

The F2 set-arm target is **not** traced here: its pin is
re-verified and its normalised stream recorded as distinct,
but naming its operation is outside this question. The traced
body itself never tail-jumps: every branch stays inside the
body and it ends in `ret`, so no boundary body is pinned from
F3.

## Stage 1 — pin re-verification

The producer authenticates the whole capture (size + SHA-256)
before any analysis, then re-derives from the binary alone: FDE
ranges via `readelf` (135,313 FDEs), every target and consumer
body hash through the section table, every target's instruction
count by fresh `objdump` disassembly, and every target's
normalised instruction stream by #2616's normalisation
definition. Any mismatch fails the producer closed. All 14
targets and all 92 consumers match their merged pins, and the
F3 placement hashes to #2616's pinned normalised-stream digest
`f9ceb9a855a558f7d973b18522faff60207eb9cdd8c380213b0b8fda3db2fa77`
— a different stream from F1's (`f9ad7013…`), so F3 is a
distinct body, not a byte-identical clone of any F1 placement.

## Stage 2 — the trace of 0x5bd6e90

- Entry (6 instructions): `movabs rax,0x7ffffffffffffff0;
  and rax,rsi` — the vector byte count, F1's mask; then
  `mov ecx,esi; and ecx,0xf` — the remainder, computed here,
  before the loop; `test rax,rax; je` straight to the tail
  when the vector count is zero.
- Main loop (`0x5bd6ec0` head, back edge `jne` at `0x5bd6f09`,
  17 instructions): one `movdqu` load from `[rdi+r8]`, two
  `pshufb` shuffles (one per nibble plane) through the table in
  `xmm1`, the mask in `xmm0`, and two `movdqu` stores to
  `[rdx+r8*2]` and `[rdx+r8*2+0x10]`; `r8` advances 16.
- Scalar tail (from `0x5bd6f0b`, 51 instructions): entered
  only when the remainder is non-zero (`test rcx,rcx` at the
  head, `je` to the `ret`). It pushes `rbx` (popped before
  the `ret`), advances the input by the vector byte count
  (`add rdi,rax` at `0x5bd6f15`), and derives the output base
  as `eax = (2 · length) & 0xffffffffffffffe0` — twice the
  vector byte count. A remainder of 1 (`cmp ecx,0x1` at
  `0x5bd6f20`) zeroes `ecx` and jumps to `0x5bd6fa8`, the
  final byte. Otherwise a pairs loop (`0x5bd6f50` head, back
  edge `jne` at `0x5bd6f9d`, count `length & 0xe` masked at
  `0x5bd6f2c`) converts two bytes per iteration through the
  table (materialised into `r10` at `0x5bd6f3a`), storing
  through `r9 = output base + output + 3` at displacements
  −3, −2, −1, 0. If the remainder is odd (`test sil,0x1` at
  `0x5bd6f9f`), one final byte is converted from `0x5bd6fa8`
  with the table re-materialised at `0x5bd6fb3` — 6 table
  lookups in the tail in total.
- The body's only external references are the two constants
  (`0x4503b0`, `0x455d40`), both read through the section
  table (.rodata file offset = VA); there are no callees, no
  other tables or data references, and no tail jump — the
  body ends in `ret` at `0x5bd6fce`.

## Stage 3 — clear-region classification

For each F3 sequence, the producer rebuilds the consumer's
basic blocks (the #2616 construction), reassembles the clear
region's bytes from the blocks #2616 pinned, and requires the
region's SHA-256 and byte count to equal the pinned
`region_sha256` / `bytes` — the region analysed is therefore
exactly the region #2616 measured, re-derived from the binary.
Classification over the region's own instructions counts:
references to the table address (which register a `lea`
materialises), table lookups (byte loads addressed through
that register), `and 0xf` and `shr 4` nibble splits, byte
stores, and backward branches (looped vs unrolled). A separate
linear tag tracker follows each stored character back through
its lookup to the `shr 4` (hi) or `and 0xf` (lo) that produced
its index, fixing the store order. Verdict rule, fixed before
the run (the #2650 rule): scalar form iff the region references
the table, performs an even number ≥ 2 of lookups, and
contains both nibble splits; all counts — including every
region's store order — are in `records.json`, so the verdicts
can be re-audited region by region
(`clear_regions.objdump.txt` retains each region's code).

Neither region is unrolled, so the unrolled-length-agreement
check of the earlier packets has no instance here (0 agree, 0
disagree); the first consumer's loop bound (32 bytes, counted
1..0x21 by 2) matches its set arm's immediate length 32, and
the second consumer's set length is a runtime value with no
immediate to agree with.

## Stage 4 — direct callers and downstream use

The producer censuses every E8/E9 byte hit in `.text` whose
relative target is the traced body and validates each hit
against the disassembly of its containing FDE (a hit must be
an instruction boundary calling/jumping to the target). The
validated result is exactly the two set-arm call sites
(`0x5bd45b4`, `0x5bd4c3f`) and no jump — the body has no other
direct caller. Downstream behaviour is pinned structurally
per consumer (the exact instruction sites are in
`records.json` under `consumers_downstream`): the `"0x"`
prefix store and the `edx = 0x42` virtual call for
`0x5bd4500`; the `0x64df480`-slot allocation call and the
three record stores for `0x5bd4bb0`.

## Explicit boundary and next question

What is **not** established: the operation of the F2 stream
(`0x5bba120`, 1 sequence) — now the last untraced set-arm
stream of the bit-9 family; the identity of the virtual
method `0x5bd4500` hands its framed text to (the vtable slot
`+0x18` of an object reached through its arguments), and who
reads the string record `0x5bd4bb0` returns; any indirect
callers of `0x5bd6e90` (through registers or slots — the
census covers direct E8/E9 transfers only); and any runtime
values.

Next question: trace the F2 tail-jump body at `0x5bba120` —
at 1,758 bytes with a prologue that loads two 32-byte halves
of its input record, it does not have the encoder's shape at
all, so the question is what operation the last bit-9 set arm
actually selects, and where its tail jump lands.

## Reproduce and validation

From repository root with the materialized pinned capture and
native GNU tools on PATH:

```sh
python3 -B tools/bit9_f3_trace_static.py --output research/work-items/RE-002-node115-bit9-f3-trace
python3 -B -m unittest discover -s tests -p test_bit9_f3_trace_static.py -v
(cd research/work-items/RE-002-node115-bit9-f3-trace && sha256sum -c MANIFEST.sha256)
```

The whole capture is authenticated before analysis, output or
native calls. Objdump/readelf receive a private byte-identical
snapshot; the snapshot path is replaced with
`<authenticated-node115>` in retained text. Wrong-release,
truncated and same-size modified public inputs are rejected
before output creation.

Focused controls alter, in an in-memory copy below the digest
gate: one byte inside the traced body `0x5bd6e90` and one
inside another set-arm target `0x5bddee0` (the re-derived body
hashes no longer match the #2616 pins), one byte of the hex
table at `0x455d40` (the traced constants no longer name the
operation), and one byte inside a consumer's clear region (the
re-derived region hash no longer matches its pin). These are
checks of the named obligations — the pin re-verification, the
constant identity, and the region pinning — not target
execution.

No captured executable/emulator, live chain/wallet/signing action
or network access is performed. No hosted-CI result or
whole-component completion is claimed.
