# RE-002: the bit-9 F1 stream traced — a lowercase hex encoder — and its selectors' clear regions are its scalar form

- Component: RE-002 build provenance / runtime-cache provenance —
  the operation behind the largest arm family of the cache
  readback (PRs #2496, #2616).
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Question: PR #2616 pinned the two arms of the 92 bit-9 cache
  consumers and stopped at the set-arm targets' entry-level
  identity.  It left as its next question, verbatim: "the eleven
  F1 targets are one instruction stream at eleven placements —
  trace that stream (its most-selected instance is `0x2a31790`,
  31 sequences) to name the operation, and check whether a
  consumer's in-body clear region is the scalar form of the same
  operation for that consumer's data type."

## Answer

**The F1 stream is a lowercase hexadecimal encoder.**  Traced in
full at its most-selected instance `0x2a31790..0x2a318cf`
(319 bytes, 76 instructions, SHA-256
`62c2bdba72c10c163ce5e18777d870756387e965f925bc01786f29dac31e08cf`):
it takes an input pointer in `rdi`, a byte length in `rsi` and an
output pointer in `rdx`, and writes two characters per input
byte, `out[2i] = table[in[i] >> 4]`, `out[2i+1] = table[in[i] &
0xf]`, where `table` is the 16-byte ASCII string
`0123456789abcdef` at `0x455d40` in `.rodata`.  The body contains
no call.  Its main loop is the SSSE3 form — 16 input bytes per
iteration: split both nibble planes (`psrld 4`, `pand` with the
16×`0x0f` mask at `0x4503b0`), shuffle each plane through the
table with `pshufb`, interleave with `punpcklbw`/`punpckhbw`,
store 32 bytes.  The remaining `length & 0xf` bytes are converted
inside the same body by a scalar tail that looks the same table
up byte by byte, hi nibble first.  Bit 9 of CPUID leaf 1 ECX —
the bit the consumers test (PR #2484) — is the bit the
architecture assigns to SSSE3, the instruction set `pshufb`
belongs to, which is exactly the capability this split requires;
that correspondence is architectural knowledge, not a name the
binary carries, and the operation is named from the traced code
alone.

**Every clear region of an F1 selector is the scalar form of
that same operation.**  Of the 98 selection sequences that reach
an F1 target (in 88 bodies), 6 are guarded calls whose clear arm
is empty — the test purely guards the call, and no scalar form
exists.  The other 92 clear regions are byte-hash-verified
against #2616's pins and then classified instruction by
instruction: **all 92** reference the same table at `0x455d40`
(by a `lea` inside the region), split bytes with `and 0xf` /
`shr 4` into table lookups, and store the looked-up characters
hi-nibble first (order checked by a linear tag tracker over each
region, 92 of 92).  Their shapes:

- 66 are loops: 52 convert 2 bytes per iteration (4 lookups),
  14 convert 3 bytes per iteration (6 lookups);
- 26 are fully unrolled for a fixed size — 13 of 20 bytes, 11 of
  8 bytes, 2 of 2 bytes — and in all 26 the number of bytes the
  region converts equals the immediate length argument the
  consumer's set arm passes to the F1 target (26 agree, 0
  disagree).

Worked example (records carry all 98): consumer
`0x298c640..0x298c76b` frames a 32-byte value as text.  Its set
arm calls `0x2a31790` with `esi = 0x20` writing at `rsp+8`,
behind a `"0x"` prefix; its clear region is a 2-bytes-per-iteration
loop (`cmp rax,0x21`, step 2, from 1 — the same 32 bytes) doing
the per-byte table conversion into the same buffer.  So for each
consumer the two arms are one operation at two speeds: the
bit-9 test chooses between the shared SSSE3 encoder and the
consumer's own scalar encoder of the identical byte string.

## Exact scope

| Role | Count |
| --- | ---: |
| tip target bodies re-verified against #2616 pins (FDE, size, SHA-256, insns, normalised stream) | 14 of 14 |
| F1 placements re-verified as one normalised stream | 11 |
| bit-9 consumer bodies re-verified against #2616 pins (SHA-256) | 92 of 92 |
| F1 selection sequences classified | 98 (88 bodies) |
| clear regions byte-hash-verified against #2616 region pins | 92 non-empty |
| clear verdicts | 92 scalar-hex-table, 6 empty, 0 other |

The F3, F4 and F2 set-arm targets are **not** traced here: their
pins are re-verified, and their normalised streams are recorded
as distinct from F1, but naming their operations is outside this
question (their selectors are 6 sequences).

## Stage 1 — pin re-verification

The producer authenticates the whole capture (size + SHA-256)
before any analysis, then re-derives from the binary alone: FDE
ranges via `readelf` (135,313 FDEs), every target and consumer
body hash through the section table, every target's instruction
count by fresh `objdump` disassembly, and every target's
normalised instruction stream by #2616's normalisation
definition.  Any mismatch fails the producer closed.  All 14
targets and all 92 consumers match their merged pins, and the
eleven F1 placements hash to the single pinned normalised-stream
digest `f9ad70135228ba7de46bd90151643d12f82c941861fcecea624035cfee28f112`.

## Stage 2 — the trace of 0x2a31790

- Entry: `movabs rax,0x7ffffffffffffff0; and rax,rsi` — the
  full-chunk byte count; if zero, control goes straight to the
  tail.
- Main loop (`0x2a317c0` head, back edge `jne` at `0x2a31806`,
  17 instructions): one `movdqu` load from `[rdi+rcx]`, two
  `pshufb` shuffles (one per nibble plane) through the table in
  `xmm1`, the mask in `xmm0`, and two `movdqu` stores to
  `[rdx+rcx*2]` and `[rdx+rcx*2+0x10]`; `rcx` advances 16.
- Scalar tail (from `0x2a31808`, 52 instructions): the
  `length & 0xf` remainder, converted two bytes at a time and one
  final byte — each byte `movzx`-loaded, low nibble looked up,
  `shr 4` looked up, hi character stored at the even output
  offset, low at the odd — through the same table (`lea` at
  `0x2a3183b` and `0x2a318b3`).  This scalar form inside the
  shared body is the reference shape the clear regions are
  checked against.
- The body's only external references are the two constants
  (`0x4503b0`, `0x455d40`), both read through the section table
  (.rodata file offset = VA); there are no other callees,
  tables or data references, and the body ends in `ret`.

## Stage 3 — clear-region classification

For each F1 sequence, the producer rebuilds the consumer's basic
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
store order.  Verdict rule, fixed before the run: scalar form
iff the region references the table, performs an even number
≥ 2 of lookups, and contains both nibble splits; all counts —
including every region's store order — are in `records.json`,
so the verdicts can be re-audited region by region
(`clear_regions.objdump.txt` retains each region's code).

## Explicit boundary and next question

What is **not** established: the operations of the F3 stream
(`0x5bd6e90`, 2 sequences — same length-mask prologue, different
remainder handling), the F4 stream (`0x5bddee0`, 3 sequences —
a chunk-of-up-to-48 entry masking `esi` with `0x30`/`0xf`, which
is not obviously this encoder) and the F2 tail-jump body
(`0x5bba120`, 1 sequence); what the consumers do with the encoded
text (the trace stops at the arms; e.g. the worked example's
`"0x"` framing is the consumer's own code, recorded here only as
the example's context); any runtime values; and the arms of the
other tested bits' families (bit 15 is the next largest, 9
consumers — #2616's boundary).

Next question: trace the F4 stream at `0x5bddee0` — its entry
chunking (up to 48 bytes, `esi & 0x30` / `& 0xf`) does not match
the hex encoder's shape, so either a second operation or a
wider-step variant of this one is hiding in the smallest
remaining set-arm family; its single consumer body's clear
region (3 sequences) is the comparison point.

## Reproduce and validation

From repository root with the materialized pinned capture and
native GNU tools on PATH:

```sh
python3 -B tools/bit9_f1_trace_static.py --output research/work-items/RE-002-node115-bit9-f1-trace
python3 -B -m unittest discover -s tests -p test_bit9_f1_trace_static.py -v
(cd research/work-items/RE-002-node115-bit9-f1-trace && sha256sum -c MANIFEST.sha256)
```

The whole capture is authenticated before analysis, output or
native calls.  Objdump/readelf receive a private byte-identical
snapshot; the snapshot path is replaced with
`<authenticated-node115>` in retained text.  Wrong-release,
truncated and same-size modified public inputs are rejected
before output creation.

Focused controls alter, in an in-memory copy below the digest
gate: one byte inside the traced body `0x2a31790` and one inside
another F1 placement `0x47358a0` (the re-derived body hashes no
longer match the #2616 pins), one byte of the hex table at
`0x455d40` (the traced constants no longer name the operation),
and one byte inside a consumer's clear region (the re-derived
region hash no longer matches its pin).  These are checks of the
named obligations — the pin re-verification, the constant
identity, and the region pinning — not target execution.

No captured executable/emulator, live chain/wallet/signing action
or network access is performed.  No hosted-CI result or
whole-component completion is claimed.
