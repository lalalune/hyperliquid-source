# RE-002: node #115 bit-9 cache tests — the two implementations each arm reaches, and the pair grouping of the 92 consumers

- Component: RE-002 build provenance / runtime-cache provenance — the
  arm side of the cache readback whose reader side PR #2496 pinned.
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Question: PR #2496 established that 102 consumer bodies read back
  only the first published cache word C0 (through slot `0x64dfa60`),
  zero-check it, refresh through slot `0x64dfa68` on the zero arm,
  and test individual bits of the word to select between
  implementations.  The largest family is the 92 consumers that test
  bit 9 (CPUID leaf 1 ECX bit 9, PR #2484's field map).  #2496
  stopped at each consumer's first bit-consuming use and left as its
  next question: for the 92 bit-9 consumers, what are the two
  implementations each arm reaches, and do all 92 bodies select the
  same pair?

## Answer

**The 92 bodies contain 104 selection sequences, and they do not
select one pair.**  Each sequence is a pair of bit-9 mask tests —
one on the loaded word C0, one on the refresh return A — and the
two tests of every sequence provably select the same ordered pair
of arms (stage 2).  What the arms reach:

- **Set arm (bit 9 = 1).**  In 103 of the 104 sequences the arm is a
  single block (13–36 bytes) whose only control transfer is a direct
  call to one of **13 shared bodies**; in the remaining sequence it
  is a tail jump to a 14th body.  No set arm does anything else: no
  second call, no indirect transfer, no in-body work beyond the
  argument setup in that one block.  The 14 target bodies are
  hash-pinned below.
- **Clear arm (bit 9 = 0).**  In 98 sequences the arm is a region of
  the consumer's own body (1–8 blocks, up to 1,753 bytes, 19,429
  bytes in total) that contains **no out-of-body transfer at all** —
  the implementation is the consumer's own inline code.  All 98
  regions are byte-distinct: no two sequences share an identical
  clear region.  In the other 6 sequences the clear arm is **empty**:
  the clear entry is the merge block itself, so the bit-9 test
  purely guards the set-arm call (the call executes, or control
  falls straight into the shared continuation).  One clear region —
  in the tail-jump body — runs to the body's own `ret` instead of a
  merge.

Grouping, exactly (stage 5): the 104 sequences fall into **17
distinct (set target, clear class) groups**, and the 92 bodies into
the same 17 groups at body level (no body's sequences disagree
about its pair).  Counted with the clear region's own hash, there
are **101 distinct exact pairs** among the 104 sequences — the only
repetition is the three guarded-call groups, whose clear arm is
empty.  The dominant groups are `call 0x2a31790` + in-body clear
(29 sequences, 26 bodies), `call 0x47358a0` + in-body clear
(26 sequences, 23 bodies) and `call 0x4ef75a0` + in-body clear
(20 sequences, 20 bodies).

**The 14 set-arm targets are four instruction streams.**  Eleven of
the thirteen call targets are 319-byte bodies with one identical
normalised instruction stream (family F1, 76 instructions; the
normalisation rewrites internal branch/call targets and
RIP-relative references self-relative and keeps external references
absolute, so the eleven streams agree on every instruction and on
every external reference — as raw bytes two members, `0x1435a90`
and `0x143e560`, differ in only 11 of 319 bytes, all in displacement
fields).  Their shared entry is an identification signature: mask
the length argument `rsi` with `0x7ffffffffffffff0`, exit early if
no full 16-byte chunk remains, load two 16-byte vector constants,
then loop over `movdqu xmm2,[rdi+rcx]` — a 16-byte-stride body.
The other three targets are one stream each: `0x5bd6e90` (F3,
319 bytes, 78 instructions; same length-mask prologue but it
computes the `rsi & 0xf` remainder before the test), `0x5bddee0`
(F4, 303 bytes, 78 instructions; no length mask — its entry masks
`esi` with `0x30` and `0xf`, a chunk-of-up-to-48 entry), and the
tail-jump target `0x5bba120` (F2, 1,758 bytes, 340 instructions;
entry builds a frame and loads `movdqa` vectors straight from the
argument structure).  No feature/ISA name is assigned to any of
this: the binary carries the CPUID attribution of the tested bit,
not names, and the targets are identified by bounds, hash and
entry, not traced inside.

| Target FDE | Bytes | Insns | Stream | Sequences | Bodies |
| --- | ---: | ---: | --- | ---: | ---: |
| `0x2a31790..0x2a318cf` | 319 | 76 | F1 | 31 | 27 |
| `0x47358a0..0x47359df` | 319 | 76 | F1 | 28 | 24 |
| `0x4ef75a0..0x4ef76df` | 319 | 76 | F1 | 22 | 22 |
| `0x5bd9eb0..0x5bd9fef` | 319 | 76 | F1 | 5 | 3 |
| `0x5bddee0..0x5bde00f` | 303 | 78 | F4 | 3 | 1 |
| `0x1435a90..0x1435bcf` | 319 | 76 | F1 | 2 | 2 |
| `0x143e560..0x143e69f` | 319 | 76 | F1 | 2 | 2 |
| `0x144d890..0x144d9cf` | 319 | 76 | F1 | 2 | 2 |
| `0x144ff90..0x14500cf` | 319 | 76 | F1 | 2 | 2 |
| `0x1454180..0x14542bf` | 319 | 76 | F1 | 2 | 2 |
| `0x5bd6e90..0x5bd6fcf` | 319 | 78 | F3 | 2 | 2 |
| `0x17432b0..0x17433ef` | 319 | 76 | F1 | 1 | 1 |
| `0x5bdeac0..0x5bdebff` | 319 | 76 | F1 | 1 | 1 |
| `0x5bba120..0x5bba7fe` | 1,758 | 340 | F2 | 1 (tail jump) | 1 |

## Exact scope

| Role | Bodies | Sequences | Sites |
| --- | ---: | ---: | ---: |
| bit-9 consumers traced here | 92 | 104 | 208 test events at 189 sites |
| set-arm target bodies pinned | 14 | — | 103 call sites + 1 tail-jump site |
| other consumers (bits 10/11/14/15 only) | 10 | — | cited from #2496, not traced |

Every consumer body and every target body is retained in full in
`consumers.objdump.txt` / `targets.objdump.txt` (each consumer is
at most 3,366 bytes, each target at most 1,758 bytes); every body's
SHA-256 is in `records.json`.  The measured denominator for the arm
claims is the 104 sequences: each was derived from the body's own
CFG, and the C0/A agreement check (stage 2) is asserted for every
one — a sequence whose two tests disagreed, or whose flag consumer
was not a single `je`/`jne`, would fail the producer closed.

## Stage 1 — census, in agreement with PR #2496

The producer re-derives the readback census by #2496's method:
relocation census of the two slots (unique: `0x64dfa60` →
`0x6500098`, `0x64dfa68` → `0x5cadd50`; no slot points at C1/C2), a
prefix-agnostic RIP-relative scan of every executable section (246
candidate sites, all 246 validated against GNU objdump at decoded
instruction starts, zero rejected), and a CFG may-analysis value
tracking of each of the 104 owner bodies.  The selection of the
bit-9 family — consumers whose C0 tested-bit set contains bit 9 —
yields the same 92 bodies with the same body hashes and the same
208 bit-9 mask-test events as #2496's retained records.  Bit 9 is
tested only by mask tests in these bodies (no `bt`, sign-test or
extraction event names bit 9), so the mask-test events are the
complete test surface of the family.

## Stage 2 — sequences: pairing the C0 and A tests

Each consumer tests bit 9 twice per selection: once on the loaded
C0 (fast path) and once on the refresh return A (after the refresh
call on the zero arm).  The producer finds, for each test, the
conditional branch that consumes its flags (scanning forward over
flag-preserving instructions only; in all 208 cases a `je`/`jne` in
the same block), derives the set/clear arm entries from the branch
polarity (`test` clears ZF iff the bit is set, so `jne` takes the
set arm and `je` takes the clear arm), and resolves entry blocks
that are a single unconditional jump — trampolines — through to the
real entry.  Tests are then grouped by their resolved
(set entry, clear entry) pair.  Three layouts occur:

- 85 sequences: two test instructions at two sites (one per word).
- 19 sequences: the load and refresh paths merge before the test,
  so a single instruction carries both events (one site, two
  words) — among them the two 3,366-byte bodies.
- the trampoline layout (2 bodies) reaches the same pair through a
  jump block on one path; grouping is by resolved entry, so these
  pair exactly like the others.

Every group is required to hold exactly the two word events and to
yield byte-identical arm descriptions from both tests; all 104
groups satisfy this.  Sequence counts per body: 82 bodies hold one
sequence, 8 hold two, 2 hold three.

## Stage 3 — arm regions

An arm's region is defined from the body CFG extended with a
virtual body-exit node: compute the immediate post-dominator (the
merge block) of the branch block, then take the blocks reachable
from the arm entry without entering the merge block or the branch
block again.  This is the code that can run on that arm before the
arms rejoin or the body is left, and it stays correct inside loops
(where plain reachability differences fail, because the shared
continuation loops back through the test).  Every control transfer
in every region is recorded in `records.json`:

- set arms: 104 regions, each exactly 1 block; 103 contain a single
  direct `call` (to an FDE start, stage 4) as their only transfer
  and exit to the merge; 1 contains a single direct `jmp` out of
  the body (tail jump) and exits to the body exit.
- clear arms: 98 non-empty regions (28 of 1 block, 54 of 3 blocks,
  15 of 8 blocks, 1 of 6 blocks) containing no call, no jump out of
  the body and no indirect transfer — the only recorded exit is to
  the merge (97) or, for the tail-jump body's clear arm, the body's
  own `ret` (1).  6 regions are empty (the guarded-call layout of
  stage 2's big bodies and their two smaller twins): the clear
  entry equals the merge block, which the region definition
  excludes, so the clear arm contributes no instruction of its own.

## Stage 4 — target identity

Each distinct out-of-body target is an FDE start, hash-pinned by
its full body SHA-256 and retained in `targets.objdump.txt`.
Identification stops at the boundary the question sets: FDE
bounds, byte size, instruction count, the first eight instructions,
and the normalised instruction stream (definition in the Answer).
Four distinct normalised streams occur among the 14 targets —
F1 (11 targets), F3, F4, F2 (one target each) — so on the set side
the 92 consumers reach, up to placement, four implementations:
one 16-byte-stride stream instantiated at eleven addresses, two
further 319/303-byte streams with different entry chunking, and
one 1,758-byte body reached by tail jump.  The arms' own callees
(the F1 entry's constant tables, the bodies' internal calls) are
recorded as stream references but not followed or traced.

## Stage 5 — the grouping

`records.json` carries the grouping at both levels with full
member lists.  By sequence (17 groups): the three dominant
`call`-target + in-body-clear groups above; eight further
in-body-clear groups (5, 3 and six of 2 sequences); three
guarded-call groups (`call 0x2a31790` / `0x47358a0` / `0x4ef75a0`
with an empty clear arm, 2 sequences each); two singleton in-body
groups (`0x17432b0`, `0x5bdeac0`); and the tail-jump group
(`0x5bba120`, 1 sequence).  By body (17 groups): identical pairs —
multi-sequence bodies never split across groups, and within a body
every sequence selects the same set target.  The exact pair count
(101) differs from the sequence count (104) only through the three
guarded-call groups, whose members share an empty clear arm and
one set target per group.

## Explicit boundary and next question

What is **not** established: what any of the four set-side streams
or the 98 clear regions compute (the trace stops at each arm's
region boundary and at each target's entry-level identity — the
selected implementations' bodies are pinned, not traced); any
feature/ISA name for bit 9's arms (the binary carries only the
CPUID attribution of the bit); runtime values; and the arms of the
other six tested bits (the bit-15 family is the next largest, with
9 consumers and the selector).  A consumer that selected an
implementation through a data table rather than a bit-9 branch
would not appear here — but within the bit-9 family the branch is
the only selection mechanism: every region's transfers are
enumerated, and none is indirect.

Next question: the eleven F1 targets are one instruction stream at
eleven placements — trace that stream (its most-selected instance
is `0x2a31790`, 31 sequences) to name the operation, and check
whether a consumer's in-body clear region is the scalar form of
the same operation for that consumer's data type.

## Reproduce and validation

From repository root with the materialized pinned capture and
native GNU tools on PATH:

```sh
python3 -B tools/bit9_arms_static.py --output research/work-items/RE-002-node115-bit9-arms
python3 -B -m unittest discover -s tests -p test_bit9_arms_static.py -v
(cd research/work-items/RE-002-node115-bit9-arms && sha256sum -c MANIFEST.sha256)
```

The whole capture is authenticated before analysis, output or
native calls. Objdump/readelf receive a private byte-identical
snapshot; the snapshot path is replaced with
`<authenticated-node115>` in retained text. Wrong-release, truncated
and same-size modified public inputs are rejected before output
creation.

Focused controls alter, in an in-memory copy below the digest gate:
one consumer's body byte (its pinned body hash changes), the
`test eax,0x200` immediate in body `0x298a490` (bit 9 becomes
bit 10 and the body leaves the bit-9 family), the disp32 of the
set-arm call in body `0x143a660` (the recorded set target changes),
one byte inside target `0x2a31790` (its pinned target hash
changes), and one slot-reference disp32 (the site leaves the
census). These are checks of the named obligations — the census
completeness, the per-bit classification, and the arm/target
pinning — not target execution.

No captured executable/emulator, live chain/wallet/signing action
or network access is performed. No hosted-CI result or
whole-component completion is claimed.
