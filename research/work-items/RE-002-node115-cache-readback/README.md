# RE-002: node #115 cache readback — who reads the three published words back, and which bits each reader tests

- Component: RE-002 build provenance / runtime-cache provenance — the
  readback side of the three-word cache whose publication the merged
  RE-002 cache-publication packet pinned.
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Question: the merged cache-publication packet pinned the suffix
  equations `C0 = A | H`, `C1 = ((B << 1) | (A >> 63)) | H`,
  `C2 = (B >> 62) | H` for the words stored through the base pointer
  in relocated slot `0x64dfa60` (RELATIVE addend `0x6500098`), and
  left as its next question a reader of the second/third words.
  PR #2474 attributed the XCR0-driven fields of A and B, PR #2484
  completed the A/B field map, and #2484 left as its next question:
  who reads the three published words back — the consumers of the
  cache at slot `0x64dfa60` beyond the publication suffix — and
  which of the mapped bits each consumer tests?

## Answer

**Only the first word is ever read back.** A validated census of
every RIP-relative reference in every executable section finds 246
instructions referencing the two slots (123 the cache-pointer slot,
123 the refresh slot), owned by 104 FDEs: the publisher (the refresh
helper, cited), the runtime-tag selector (cited, merged packet), and
**102 consumer bodies** measured here. Every one of the 102
consumers loads C0 through the slot pointer and no other word: 127
C0 loads, zero loads of C1 or C2 — and there is no other way the
words are reached (stage 1). **C1 and C2 have no reader anywhere in
the binary**, so the B-carried fields of C1 (bits 1–12) and the
H-set bit at C1 bit 0 are published but never consumed, and C2 —
which PR #2484 showed equals H on every path — is never read at all.

Each consumer runs the same idiom: load C0, zero-check it (all 102
bodies; the check is exactly "not yet published", since C0 is zero
before the first publication and always has the H marker bit 63 set
afterwards), call the refresh helper through its slot on the zero
arm (123 refresh call sites across the 103 reading bodies), and test
individual bits of the word to select between implementations. On
the refresh arm the consumer tests the **same** bits on the helper's
raw return A instead of re-loading C0 — in all 102 consumers (and
in the selector) the bit set tested on A equals the bit set tested
on C0; A and C0 differ only in bit 63, which nobody tests.

The complete set of bits any reader tests, with the field-map
attribution of PR #2484 (drivers quoted verbatim; C0 bit *i* is
A bit *i* for *i* < 63):

| C0 bit | tested by | driver (PR #2484 field map) |
| --- | ---: | --- |
| 9 | 92 consumers | cpuid leaf 1 ecx bit 9 |
| 15 | 9 consumers + selector | cpuid leaf 7 subleaf 0 ebx bit 5, gated by xcr0 bits 1,2 fall-through |
| 11 | 2 consumers | cpuid leaf 1 ecx bit 20 |
| 14 | 3 consumers | cpuid leaf 1 ecx bit 28, gated by xcr0 bits 1,2 fall-through |
| 10 | 1 consumer + selector | cpuid leaf 1 ecx bit 19 |
| 19 | selector only | cpuid leaf 7 subleaf 0 ebx bit 16, gated by (xcr0 & 0xe0) == 0xe0 and cpuid leaf 1 ecx bits 12,29 both set (extra block) |
| 25 | selector only | the constant 1, selected by cpuid leaf 7 subleaf 0 ebx bit 31, under the same extra-block gate |

Every other bit of C0 — including bit 63, the H publication marker
itself — is tested by no reader. Per-body bit sets are small: 91
consumers test bit 9 alone, 6 test bit 15 alone, 2 test bits 11+15,
2 test bit 14 alone, and one body (`0x5bba800..0x5bbb030`) tests
bits 9, 10, 14 and 15 in four separate load/check/test sequences.
Nineteen bodies contain two or more independent slot-load sequences.

**No consumer forwards a word.** Across all 102 consumers there is
no store of a loaded word, no call that receives a loaded word in an
argument register the call block sets, and no return of a loaded
word; the cache base pointer itself never leaves the body that
loaded it (no pointer store, pass or address-taken event). The one
partial exception is liveness, not forwarding: in the mode-byte
body `0x2e567b0..0x2e571df`, a copy of the word may still be live in
`rcx` across three call sites (`0x2e56d42`, `0x2e56e72`,
`0x2e5714a`) on some paths — the call blocks set their argument
registers from unrelated values and never set `rcx` from the word.
That body and its twin `0x2e57640..0x2e577fc` extract bit 11 and
sign-test bit 15 and store a derived mode byte at `0x64ffef0`; the
stored byte is a function of the extracted bit, not the word.

## Exact scope

| Role | Bodies | Bytes | Sites |
| --- | ---: | ---: | ---: |
| publisher (refresh helper, cited) | 1 | 1,674 | 1 slot load, 3 word stores |
| selector (merged runtime-tag packet, cited) | 1 | 136 | 1 slot load, 4 refresh calls, 4 C0 loads |
| consumers (this packet) | 102 | 62,011 | 121 slot loads, 119 refresh calls, 127 C0 loads |

The measured denominator is **104 complete FDEs, 63,821 bytes**,
with all 246 slot-referencing instructions validated at decoded
instruction starts. Every consumer body is retained in full in
`consumers.objdump.txt` (each is at most 3,366 bytes); each body's
SHA-256 is in `records.json`. The publisher and selector records are
included for census completeness and are cross-checked against the
merged packets (stage 4); their semantics are cited, not
re-derived. This is not a raw-equal or normalised cross-function
claim.

## Stage 1 — census and completeness

- **Slots.** `.rela.dyn` contains exactly one slot with addend
  `0x6500098` (`0x64dfa60`) and one with addend `0x5cadd50`
  (`0x64dfa68`, the refresh helper); no slot points at C1 or C2.
- **References.** A prefix-agnostic scan for modrm mod=00/rm=101 in
  every executable section (which covers legacy, REX, 0F-escape and
  VEX RIP-relative forms) produces 246 candidate sites for the two
  slots and **zero** for the three word addresses themselves; a
  movabs scan for all five addresses finds zero materialisations.
  All 246 candidates validate against GNU objdump output: a decoded
  instruction starts at the candidate's instruction, its operand
  target equals the censused address, and the disp32 bytes match.
  Zero candidates are rejected. There are zero direct (E8) calls to
  the refresh helper and zero to the selector anywhere in `.text` —
  the helper is reached only through its slot, the selector only
  through its own slot `0x64df488` (merged packet).
- **Neighbourhood.** References to `.bss` addresses within
  ±0x20 bytes of the triple (targets `0x6500078`–`0x65000b0`) were
  censused separately (42 sites, in `records.json`): they are
  direct value accesses to adjacent statics — a `lock cmpxchg` lock
  dword at `0x6500080`, flag bytes at `+3/+4` and neighbours above
  C2 — not address formations, and none is offset into the triple.
  Within the 102 consumers, no load through the cache pointer uses
  an offset outside {0, 8, 16} (zero `outside_triple_load` events),
  and offsets 8 and 16 never occur: the only offset ever
  dereferenced is 0.

## Stage 2 — the consumer idiom

`tools/cache_readback_static.py` runs a CFG may-analysis per body:
registers and stack cells map to sets of possible tracked values
(the base pointer, each loaded word, the refresh return), joined at
block entries, so a use is recorded only when a real control path
can carry the value to it. Recorded per body (521 events in
`records.json`): every C0 load with its site and width, every
zero check (131), every refresh call (123), every bit-consuming use
— mask tests (220), sign tests (20), shift and bit extractions
(6 each) — and
every forwarding-class event. The zero check always guards the
refresh call: a body that finds C0 zero calls the helper and then
applies its bit tests to the returned A; a body that finds C0
nonzero tests the loaded word directly. 19 bodies repeat the whole
sequence for a second (or third, or fourth) bit.

## Stage 3 — what the tested bits select

The bit tests choose between two code paths inside the consumer
(implementation arms, tail-jumped function pointers, or a stored
mode byte). Following the prior packets, no feature/ISA name is
assigned to any bit or arm: the binary carries the CPUID
attribution (stage table above), not names. Two structural facts
fall out of the census:

- The detector's readback surface is seven bits of one word. The
  field map's remaining 57 C0 fields, all of C1's B-carried fields,
  the XCR0 H-set at C1 bit 0, and C2 have no consumer; a
  reimplementation that published only C0's seven tested bits plus
  the zero/H publication behaviour would be indistinguishable to
  every reader in this binary.
- Four of the seven tested bits (14, 15, 19 and 25) exist only
  on XCR0-gated composition paths
  (PR #2474); on a machine that never enters those regions the
  corresponding arms are never taken. (Bit 15's testers include
  bodies whose only test is the 16-bit sign test `test ax,ax; js`.)

## Stage 4 — cross-validation against the merged packets

- The publisher record re-derives the merged publication packet's
  suffix endpoints independently: the helper's only slot load is at
  `0x5cae3a1`, and its only stores through the pointer are at
  offsets 0, 8, 16 (`0x5cae3a8`, `0x5cae3b6`, `0x5cae3c4`) — the three
  pinned stores, with no other cache write anywhere.
- The selector record agrees with the merged runtime-tag packet's
  theorem: four cold refresh call sites, C0 loads at
  `0x160bee8`/`0x160bef7`/`0x160bf09`/`0x160bf18`, and the tested
  bits {19, 25, 15, 10} on the stable word. This packet adds only
  that on the cold arms the same bits are tested on the refresh
  return A.
- No consumer contradicts PR #2474's attribution: the bits gated by
  XCR0 terms are tested exactly where the gates can have produced
  them, and C2 — no XCR0-driven field (PR #2474) and constant H
  (PR #2484) — is read by nobody.

## Explicit boundary and next question

What is **not** established: any feature/ISA meaning of the seven
tested bits or of the arms they select; what the selected
implementations compute (the trace stops at each consumer's first
bit-consuming use, per the question's boundary — the arms'
targets are named in the retained exports but their bodies are not
traced); runtime values of the words; and any concurrency property
of the readback (a reader that observes a partially published
triple is indistinguishable here, since only C0 is read and its H
bit makes the zero check a publication check). A reader that
computed the cache address arithmetically from a different base —
rather than through the slot or a direct reference — would escape
the census; stage 1 bounds that gap to the inspected neighbourhood
window and to the absence of pointer escapes from the 102 bodies.

Next question: for the largest family — the 92 bit-9 consumers —
what are the two implementations each arm reaches, and do all 92
bodies select the same pair?

## Reproduce and validation

From repository root with the materialized pinned capture and
native GNU tools on PATH:

```sh
python3 -B tools/cache_readback_static.py --output research/work-items/RE-002-node115-cache-readback
python3 -B -m unittest discover -s tests -p test_cache_readback_static.py -v
(cd research/work-items/RE-002-node115-cache-readback && sha256sum -c MANIFEST.sha256)
```

The whole capture is authenticated before analysis, output or
native calls. Objdump/readelf receive a private byte-identical
snapshot; the snapshot path is replaced with
`<authenticated-node115>` in retained text. Wrong-release, truncated
and same-size modified public inputs are rejected before output
creation.

Focused controls alter, in an in-memory copy below the digest gate:
one consumer's body byte (its pinned body hash and records change),
the `test eax,0x200` immediate in body `0x298a490` (bit 9 becomes
bit 10 in the recomputed record and the retained records no longer
match), one slot-reference disp32 (the site leaves the census), and
the refresh slot's relocation addend (the slot census rejects it).
These are checks of the named obligations — the census completeness,
the site validation, and the per-bit classification — not target
execution.

No captured executable/emulator, live chain/wallet/signing action
or network access is performed. No hosted-CI result or
whole-component completion is claimed.
