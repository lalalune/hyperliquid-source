# RE-001: pin node #115 tagged-value widening conversion at 0x57ae540 end to end

Bounded question: what does the leaf routine at 0x57ae540
(FDE 0x57ae540..0x57ae642, 258 bytes) compute for every input
it accepts — the full 22-case dispatch table, each case's
output tag, payload transform and placement, the exact set of
output bytes written, and the contract its 149 call sites rely
on?

Target: node #115 work binary `work/hl-node-115.bin`,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(bound to provenance/artifacts.json for node #115).

The routine has no RE-002 vendor-census label (checked against
the census corpus) and no name is claimed for it here. It is
described by observed semantics only: a width-normalizing
conversion from one tagged-value representation — per-width
integer and float variants, two 16-byte payload shapes, and
unit variants — to a widened one whose payload kinds are u64,
i64, f64, a u32 slot, two distinct 16-byte kinds, and unit
kinds. Which source types these representations belong to is
not established by this packet (see Not claimed).

Relation to existing work: the start address 0x57ae540
appears in no merged work item and in no open pull request
(swept by full-text search of the base tree and by title/body
search of all 666 open PRs at sweep time), and no merged or
open packet answers this question. The RE-005 varint-size
family is a different question (a counter advance, not a
value conversion) and does not cite this body.

## What is pinned

Signature (System V, both pointers supplied by every sampled
call site in the same shape: rdi is a fresh output slot, rsi
the input slot):

    convert(out: *mut u8 /* rdi */, inp: *const u8 /* rsi */)

Dispatch (0x57ae540..0x57ae553, main.txt): the tag byte at
[inp] is zero-extended and indexes a 22-entry jump table at
0x931abc in .rodata (table.txt); each entry is a signed
32-bit offset from the table base and the body jumps to
table + offset. There is **no bounds check**: an input tag
>= 22 leaves the table, so tags 0..21 are a caller-side
contract, not something this body enforces. The body makes
no calls, reads no memory besides the input slot and the
table, and writes nothing besides the output slot.

The 22 cases (offsets are from the slot base; the output tag
byte at [out] is written by every case, and no other output
bytes are written — bytes outside a case's write set keep
whatever the caller's slot already held):

| in tag | case      | read                | write                    | out tag |
|--------|-----------|---------------------|--------------------------|---------|
| 0      | 0x57ae5d0 | byte at [1]         | byte at [1]              | 0       |
| 1      | 0x57ae5dc | u8 at [1]           | u64 at [8], zero-extended | 1      |
| 2      | 0x57ae59d | u16 at [2]          | u64 at [8], zero-extended | 1      |
| 3      | 0x57ae5b7 | u32 at [4]          | u64 at [8], zero-extended | 1      |
| 4      | 0x57ae570 | u64 at [8]          | u64 at [8]               | 1       |
| 5      | 0x57ae5e9 | i8 at [1]           | i64 at [8], sign-extended | 2      |
| 6      | 0x57ae604 | i16 at [2]          | i64 at [8], sign-extended | 2      |
| 7      | 0x57ae5c3 | i32 at [4]          | i64 at [8], sign-extended | 2      |
| 8      | 0x57ae621 | u64 bits at [8]     | i64 at [8], bits unchanged | 2     |
| 9      | 0x57ae58a | f32 at [4]          | f64 at [8], cvtss2sd     | 3       |
| 10     | 0x57ae612 | f64 at [8]          | f64 at [8]               | 3       |
| 11     | 0x57ae565 | u32 at [4]          | u32 at [4]               | 4       |
| 12     | 0x57ae57d | 16 bytes at [16]    | 16 bytes at [8]          | 5       |
| 13     | 0x57ae5f7 | 16 bytes at [8]     | 16 bytes at [8]          | 5       |
| 14     | 0x57ae558 | 16 bytes at [16]    | 16 bytes at [8]          | 6       |
| 15     | 0x57ae5aa | 16 bytes at [8]     | 16 bytes at [8]          | 6       |
| 16     | 0x57ae553 | tag only            | —                        | 8       |
| 17     | 0x57ae553 | tag only            | —                        | 8       |
| 18     | 0x57ae638 | tag only            | —                        | 7       |
| 19     | 0x57ae63d | tag only            | —                        | 9       |
| 20     | 0x57ae62e | tag only            | —                        | 10      |
| 21     | 0x57ae633 | tag only            | —                        | 11      |

Points a reconstruction must reproduce exactly:

- Tags 3 and 11 read the same u32 at [4] but are different
  conversions: tag 3 widens it to a u64 at [8] under output
  tag 1; tag 11 stores it back as a u32 at [4] under output
  tag 4. The input tag, not the payload, chooses.
- Tags 12/14 read the 16-byte payload at [16], tags 13/15
  at [8]; the pairs land under different output tags
  (5 vs 6). A reader that assumes one payload offset for
  all 16-byte variants is wrong for two of the four.
- The input slot must expose 32 readable bytes for tags
  12 and 14; the output slot's written extent is 24 bytes
  (tag byte plus the [8]..[24] payload of the 16-byte
  cases). The input slot is never written.
- rax on exit is a case-dependent residue, pinned here as
  observed machine state (it is not a documented return
  value and no sampled caller reads it): payload cases that
  load the value into rax leave (stored value with its low
  byte replaced by the output tag); cases that never reload
  rax after the dispatch (f32/f64, the 16-byte copies, the
  unit cases) leave (case address with its low byte
  replaced by the output tag); input tag 0 leaves 0.

## Census (whole-file scan, reproduced by census.py)

- 149 direct call sites, every one confirmed twice: by
  objdump decoding at the site (census.py) and by linear
  disassembly of the enclosing FDE. 0 byte-scan candidates
  were rejected. The sites sit in 146 distinct caller FDEs
  (callers.tsv); the adjacent FDE at 0x57ae7b0 is one of the
  callers. Sampled sites all set up rdi as a fresh stack
  slot and rsi as the input pointer immediately before the
  call.
- 0 tail jumps to the body, 0 stored qwords equal to its
  address anywhere in the file, 0 RELATIVE relocation
  addends naming it: the 149 direct calls are the only way
  in.

## Validation

- tools/value_widen_57ae540.py is a per-case transcription
  of the body. tests/test_value_widen_57ae540.py compares
  it against an independent declarative spec of the table
  above on directed edge payloads and deterministic
  randomized buffers — 47,436 pure-model checks, all
  passing — including the exact write set per case
  (established with two different sentinel fills), input
  immutability, and the rax residue.
- Separately, the lane ran the packet's differential.py:
  the real body under Unicorn emulation on all 22 tags
  with directed payloads (including f32 sNaN/qNaN payloads,
  ±0, infinities) and 500 randomized buffers per tag —
  11,176 runs, 0 mismatches in the output slot or the rax
  residue; the input slot came back byte-identical and no
  byte past the 24-byte output extent was written. The
  f32 -> f64 widening, including NaN payloads, is pinned
  bit-for-bit by this differential.
- verify.py re-checks the binary digest, the MANIFEST,
  both excerpts byte-for-byte against fresh tool runs,
  every excerpt instruction against the raw binary, the
  frame lines against a fresh readelf dump, the census
  against a fresh census.py run, the records (including
  the body and jump-table SHA-256 values against the raw
  binary), and the model tests.

## Evidence format

- main.txt: verbatim objdump excerpt of the body
  (0x57ae540..0x57ae642; FDE line in frames.txt).
- table.txt: verbatim objdump contents dump of the jump
  table (0x931abc..0x931b18).
- frames.txt: the readelf frame-dump FDE lines for the
  body and all 146 caller FDEs.
- callers.tsv: every confirmed direct call site with its
  smallest enclosing FDE and a mechanical setup note (the
  last rdi/rsi-writing instructions before the call).
- relocations.txt: intentionally empty — the census finds
  no stored qwords and no RELATIVE addends for the target.
- records.json: the semantic record verify.py checks.
- census.py / export_excerpts.py / differential.py: the
  census, excerpt regeneration, and Unicorn differential
  described above. census.py and export_excerpts.py need
  only the standard library plus objdump/readelf;
  differential.py additionally needs the unicorn package.

## Not claimed

- The source-level identity of the two value
  representations (which crate or module defines them),
  and any variant names. Tags are identified by number
  and payload shape only.
- What the 16-byte payloads mean (integer, string parts,
  or anything else): they are copied verbatim, and their
  interpretation is the callers' question.
- Behaviour for input tags >= 22. The body performs no
  bounds check, so such inputs jump through stale table
  space; they are outside every observed caller's
  contract and were not emulated.
- The bodies of the 146 caller FDEs (sites, ranges and
  argument setup only), including the adjacent wrapper
  FDE at 0x57ae7b0.
- Native execution, a Rust reimplementation, or byte
  equality of any reconstruction. The emulation result is
  Unicorn's, on the digest-verified binary, for the
  inputs described.
