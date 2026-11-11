# RE-014: node115 postaggregate threshold arithmetic

Research allocation: fees/volume, matching retained raw_vlm.rs and scaled_vlm.rs
Location leads, without assigning economic units. Sole target Linux x86-64
node115, SHA256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
105896032 bytes. Base05bc2de303c05525b71e7e257426e741bc66a390. Unre-based ELF VAs.
New MIT work independently authored; no unlicensed inferred source read/copied.
Accepted parent #2277 records the tag/threshold boundary but explicitly leaves
the reciprocal's full mathematical conversion unclosed. The different fee
point classifier #2689 binds3876290/3ebfdb0, not this function or question.

## Included points and unresolved behavior

Complete containing FDE2a82220..2a825b2 is914 bytes /214 instructions, retained
with actual FDE/CIE and agreeing GNU/Capstone exports. It is STATIC CONTEXT.
Only112 bytes /24 instructions in three independently seeded spans are modeled:

- Entry2a824d6..2a82527: seed R15=A, RBP=P, RBX=B, R14=bound,
  R13=0x8000000000000018 and RSP with an8-byte raw L at+0x50.
- Independent post-sum-diagnostic point2a82581..2a82598: fresh raw A/P/B/bound,
  same explicit head/L premises. This is not an injected callback return.
- Independent post-secondary-diagnostic point2a825aa..2a825b2: fresh retained
  sum inRBX, head andL premises. Unused fixture input words are canonical zero.

All other incoming registers/flags start unknown. Calls/writes/escaped PCs and
unknown observations fail closed. Stop BEFORE2a82572 or2a82598 as A/B boundary
markers, or BEFORE2a82527 to observe raw RDX quotient, RCX threshold and R13 head.
A/B are not native errors, returns or proven panics. Every selected start is
visited; no opaque handler, aggregate or initialization helper is supplied.
The three point functions remain separate; they are not a composed execution
or a guarantee that a handler returns normally or preserves fixture state.

The original entry checks unsigned addition overflow before the secondary
B>bound guard. The independent sum continuation saturates the fresh A+P;
the secondary continuation restores its fresh saved sum. The normal quotient
is exactly floor(sum/500000000), proven for every u64 in PROOF.md. The threshold
is min(quotient,4000)+1000. Strict L<threshold chooses head0x800000000000001b;
equality keeps0x8000000000000018. Unclamped quotient is also observed so the
ceiling cannot hide large-input errors. Source names are contextual leads;
volume units, domain reachability and business policy remain unknown.

## Pre-Rust target freeze

Original instructions produced8916 distinct point fixtures:5955 normal raw
triples,2754 secondary frontiers and207 sum frontiers. Eleven actual byte COW
controls distinguish overflow precedence, bound comparison, reciprocal literal,
both shifts, clamp/ceiling/baseline, strict equality, saturation and retained
sum width. None writes the capture. Raw target SHA is checked before/after.
The denominator is selected24 instructions, not a whole214-instruction claim.

Input boundaries use the identified divisor as stimuli only. Expected outputs
come solely from original instructions, never a high-level formula or Rust.
The universal reciprocal proof is algebraic, not2^64 executed cases. Independent
raw point states need not be caller-reachable. FREEZE.json pins input/output
stream hashes; target-smoke.tsv retains52 original representative rows.

```
python3 research/work-items/RE-014-raw-threshold-115/freeze.py --output <new-directory> --objdump <GNU-objdump>
python3 research/work-items/RE-014-raw-threshold-115/native.py
python3 tools/verify_packets.py
```

Python3.12.14, Capstone5.0.6, GNUobjdump2.47.20260726, unchanged licensed project
instruction evaluator and existing MIT ELF helper. The original code is only
interpreted offline; no captured executable/Unicorn, network service, signing,
chain or wallet action runs. All92 gates remain false; no compiled body-byte,
whole-node, original Rust type/ABI or helper-closure claim. Next: recover actual
aggregate producers and caller-owned domain before asserting application units.
The parent records/frames/relocations remain attributed/hash-pinned supporting
context, not a second static-discovery contribution or peer review.

## Independently authored Rust

Frozen expectations were committed at0ba8b85de06cfb23832b3aeb06ff2b369ed917a3
before source existed. The no_std library exposes the three separately qualified
point functions, not an opaque handler implementation. Both rustc1.94.1 opt0/3
input-only clients match all8916 original observations; optimized own-library
repeat is identical. Two ordinary tests exercise the original52-row smoke and
the independently captured overlap-guard case. Ten compiled corruptions all
differ from the original full corpus and fail their ordinary tests. Compiler,
source/driver/input/output hashes and exact mismatch counts are retained.

The first complete control-run attempt exposed a sample weakness: all8916-row
comparisons detected the wrong guard ordering (88 mismatches), but the52-row
representative smoke did not. The original frozen smoke and expectations were
preserved. A Rust assertion for already-sealed row4088 (MAX+1 and B>bound)
was added; its originalA result predates Rust. The complete matrix was rerun.
This is not a claim that the first failed control sequence passed.

```
python3 research/work-items/RE-014-raw-threshold-115/build.py --rustc <rustc1.94.1> --output <new-directory>
python3 -m unittest discover -s tests -p test_node115_raw_threshold.py -v
```

macOSarm64/edition2021 is a research build, not an original Linux recipe or
compiled-body identity. New source has no external dependencies or invented
original Cargo graph. Local catalogue checks may use the exact already-submitted
#2655 immutable-snapshot performance fix to avoid its measured repeated-read
blocker. Such validation is explicitly labelled with both helper hashes and
restores the baseline helper before commit; it is not an exact unmodified-head
execution claim. Native/Rust tests and other checks use baseline tooling.

## Scoped repository verification

Six focused tests, formatting, Clippy, twelve packet-integrity tests, doctor,
artifact/import/packet verification, catalogue generation/check and actual
inventory reproduction pass. Exact command timings are in repository-checks.json.
Only the catalogue steps use the explicitly recorded already-submitted snapshot
fix; the baseline helper is restored byte-for-byte and is not part of this diff.
This scope differs from running those two commands on an unmodified head.
The earlier independent full-CI585/584-file baselines do not substitute for
this new PR's own pending upstream CI. No combined local full pass is claimed.
