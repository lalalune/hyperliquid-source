# RE-002: the bit-9 F4 stream traced — the same lowercase hex encoder in a bounded variant — and its selectors' clear regions are its scalar form

- Component: RE-002 build provenance / runtime-cache provenance —
  the operation behind the smallest arm family of the cache
  readback (PRs #2496, #2616, #2650).
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Question: PR #2616 pinned the set arms of the 92 bit-9 cache
  consumers and stopped at each target's entry-level identity;
  PR #2650 traced the largest stream, F1, as a lowercase hex
  encoder and recorded of F4 only that it is "the F4 stream
  (`0x5bddee0`, 3 sequences — a chunk-of-up-to-48 entry masking
  `esi` with `0x30`/`0xf`, which is not obviously this encoder)".
  It left as its next question, verbatim: "trace the F4 stream at
  `0x5bddee0` — its entry chunking (up to 48 bytes, `esi & 0x30` /
  `& 0xf`) does not match the hex encoder's shape, so either a
  second operation or a wider-step variant of this one is hiding
  in the smallest remaining set-arm family; its single consumer
  body's clear region (3 sequences) is the comparison point."

## Answer

**Neither alternative: the F4 stream is the same operation as
F1 — a lowercase hexadecimal encoder — in a bounded variant.**
Traced in full at its sole placement `0x5bddee0..0x5bde00f`
(303 bytes, 78 instructions, SHA-256
`92ee8275b48be1f6a05f6a9549f936c03738c3c1911d5fb57b20eb7d0a5a08da`):
it takes an input pointer in `rdi`, a byte length in `rsi` and an
output pointer in `rdx`, contains no call, and writes two
characters per converted byte, `out[2i] = table[in[i] >> 4]`,
`out[2i+1] = table[in[i] & 0xf]`, where `table` is the same
16-byte ASCII string `0123456789abcdef` at `0x455d40` in
`.rodata` that F1 reads, next to the same 16×`0x0f` nibble mask
at `0x4503b0`.  Its main loop is F1's SSSE3 loop — 16 input bytes
per iteration, both nibble planes shuffled through the table with
`pshufb`, interleaved with `punpcklbw`/`punpckhbw`, 32 bytes
stored.

What differs is only the chunking, and it makes the variant
narrower, not wider-step.  F1 masks the length with
`0x7ffffffffffffff0` and vectorises all but the last 15 bytes.
F4 computes its vector byte count as `length & 0x30` — at most
48 bytes, three chunks — and its remainder as `length & 0xf`;
bits of the length above bit 5 select nothing, so the body
converts exactly `(length & 0x30) + (length & 0xf)` =
`length & 0x3f` bytes and is exact for lengths up to 63.  The
remainder is converted by an in-body scalar tail: a two-byte
loop over `remainder & 0xe` whose output base is derived as
`(2 * length) & 0x60` = twice the vector byte count, plus one
final byte when the remainder is odd — the same table, hi nibble
first.  The truncation above 63 bytes never fires in the use the
binary makes of this body: its single selecting consumer passes
only the length constants 32, 2 and 2.

**Every clear region of an F4 selector is the scalar form of
that same operation.**  All 3 selection sequences live in the
single consumer body `0x5bddcb0..0x5bdded8` (SHA-256
`211de0530988c1a3e75f3da2fcc067183e792deef318eb5c1fa8dd7d9d88be4f`),
and all 3 clear regions are byte-hash-verified against #2616's
pins and then classified instruction by instruction: **all 3**
reference the same table at `0x455d40` (by a `lea` inside the
region), split bytes with `and 0xf` / `shr 4` into table lookups,
and store the looked-up characters hi-nibble first (order checked
by a linear tag tracker over each region, 3 of 3).  Their shapes:

- sequence 0 (set length 32): a loop converting 2 bytes per
  iteration over the same 32 bytes, into the same output buffer;
- sequences 1 and 2 (set length 2 each): fully unrolled for
  2 bytes — and in both, the number of bytes the region converts
  equals the immediate length argument the consumer's set arm
  passes to the F4 target (2 agree, 0 disagree).

Worked example (records carry all 3): the consumer frames a
32-byte value as text.  Its set arm calls `0x5bddee0` with
`esi = 0x20` writing at `rsp+0x10`, behind a `"0x"` prefix stored
at `rsp+0xe`; its clear region is the 2-bytes-per-iteration loop
(`cmp rax,0x21`, step 2, from 1 — the same 32 bytes) doing the
per-byte table conversion into the same buffer.  So for this
consumer the two arms are one operation at two speeds: the bit-9
test chooses between the shared SSSE3 encoder and the consumer's
own scalar encoder of the identical byte string — exactly the
F1 pattern, in the smallest family.

## Exact scope

| Role | Count |
| --- | ---: |
| tip target bodies re-verified against #2616 pins (FDE, size, SHA-256, insns, normalised stream) | 14 of 14 |
| bit-9 consumer bodies re-verified against #2616 pins (SHA-256) | 92 of 92 |
| F4 placements traced | 1 (`0x5bddee0`, 3 sequences) |
| F4 selection sequences classified | 3 (1 body) |
| clear regions byte-hash-verified against #2616 region pins | 3 |
| clear verdicts | 3 scalar-hex-table, 0 empty, 0 other |

The F3 and F2 set-arm targets are **not** traced here: their
pins are re-verified, and their normalised streams are recorded
as distinct from F4, but naming their operations is outside this
question (their selectors are 3 sequences).

## Stage 1 — pin re-verification

The producer authenticates the whole capture (size + SHA-256)
before any analysis, then re-derives from the binary alone: FDE
ranges via `readelf` (135,313 FDEs), every target and consumer
body hash through the section table, every target's instruction
count by fresh `objdump` disassembly, and every target's
normalised instruction stream by #2616's normalisation
definition.  Any mismatch fails the producer closed.  All 14
targets and all 92 consumers match their merged pins, and the
F4 placement hashes to #2616's pinned normalised-stream digest
`d54230ce448978ed933e1f2326524c56294de3c5ef4ba77b116a18a18303c00a`.

## Stage 2 — the trace of 0x5bddee0

- Entry: `mov eax,esi; and eax,0x30` — the vector byte count,
  at most 48; `mov ecx,esi; and ecx,0xf` — the remainder.  If
  the vector count is zero, control goes straight to the tail.
- Main loop (`0x5bddf10` head, back edge `jne` at `0x5bddf59`,
  17 instructions): one `movdqu` load from `[rdi+r8]`, two
  `pshufb` shuffles (one per nibble plane) through the table in
  `xmm1`, the mask in `xmm0`, and two `movdqu` stores to
  `[rdx+r8*2]` and `[rdx+r8*2+0x10]`; `r8` advances 16 — F1's
  loop shape, with `r8` as the counter where F1 uses `rcx`.
- Scalar tail (from `0x5bddf5b`, 51 instructions): entered when
  the remainder is non-zero.  The output base for the remainder
  is derived as `eax = (2 * length) & 0x60` (`0x5bddf68`/
  `0x5bddf6b`) — twice the vector byte count.  A pairs loop
  (`0x5bddf90` head, back edge `jne` at `0x5bddfdd`, 19
  instructions) converts `remainder & 0xe` bytes (count masked
  at `0x5bddf7a`) two at a time through the table (materialised
  by the `lea` at `0x5bddf88`), hi character stored at the even
  output offset, low at the odd.  If the remainder is odd
  (`test sil,0x1` at `0x5bddfdf`), one final byte is converted
  after `add rdx,rax` (`0x5bddfe8`) with the table re-materialised
  at `0x5bddff3` — 6 table lookups in the tail in total.  The
  remainder-1 case enters the final byte directly.
- The body's only external references are the two constants
  (`0x4503b0`, `0x455d40`), both read through the section table
  (.rodata file offset = VA); there are no other callees, tables
  or data references, and the body ends in `ret`.

## Stage 3 — clear-region classification

For each F4 sequence, the producer rebuilds the consumer's basic
blocks (the #2616 construction), reassembles the clear region's
bytes from the blocks #2616 pinned, and requires the region's
SHA-256 and byte count to equal the pinned `region_sha256` /
`bytes` — the region analysed is therefore exactly the region
#2616 measured, re-derived from the binary.  Classification over
the region's own instructions counts: references to the table
address (which register a `lea` materialises), table lookups
(byte loads addressed through that register), `and 0xf` and
`shr 4` nibble splits, byte stores, and backward branches
(looped vs unrolled).  A separate linear tag tracker follows
each stored character back through its lookup to the `shr 4`
(hi) or `and 0xf` (lo) that produced its index, fixing the
store order.  Verdict rule, fixed before the run (the #2650
rule): scalar form iff the region references the table, performs
an even number ≥ 2 of lookups, and contains both nibble splits;
all counts — including every region's store order — are in
`records.json`, so the verdicts can be re-audited region by
region (`clear_regions.objdump.txt` retains each region's code).

## Explicit boundary and next question

What is **not** established: the operations of the F3 stream
(`0x5bd6e90`, 2 sequences — same length-mask prologue as F1,
different remainder handling) and the F2 tail-jump body
(`0x5bba120`, 1 sequence) — the last two untraced set-arm
streams; what the consumer does with the encoded text beyond
the arms (e.g. the worked example's `"0x"` framing and the
second value's framing are the consumer's own code, recorded
here only as the examples' context); any direct callers of
`0x5bddee0` outside the bit-9 consumer census; and any runtime
values.

Next question: trace the F3 stream at `0x5bd6e90` — it shares
F1's arbitrary-length prologue but handles its remainder
differently, so the question is which part of the encoder, if
any, it reuses, and whether its 2 selectors' clear regions are
again the scalar form.

## Reproduce and validation

From repository root with the materialized pinned capture and
native GNU tools on PATH:

```sh
python3 -B tools/bit9_f4_trace_static.py --output research/work-items/RE-002-node115-bit9-f4-trace
python3 -B -m unittest discover -s tests -p test_bit9_f4_trace_static.py -v
(cd research/work-items/RE-002-node115-bit9-f4-trace && sha256sum -c MANIFEST.sha256)
```

The whole capture is authenticated before analysis, output or
native calls.  Objdump/readelf receive a private byte-identical
snapshot; the snapshot path is replaced with
`<authenticated-node115>` in retained text.  Wrong-release,
truncated and same-size modified public inputs are rejected
before output creation.

Focused controls alter, in an in-memory copy below the digest
gate: one byte inside the traced body `0x5bddee0` and one inside
another set-arm target `0x5bd6e90` (the re-derived body hashes no
longer match the #2616 pins), one byte of the hex table at
`0x455d40` (the traced constants no longer name the operation),
and one byte inside a consumer's clear region (the re-derived
region hash no longer matches its pin).  These are checks of the
named obligations — the pin re-verification, the constant
identity, and the region pinning — not target execution.

No captured executable/emulator, live chain/wallet/signing action
or network access is performed.  No hosted-CI result or
whole-component completion is claimed.
