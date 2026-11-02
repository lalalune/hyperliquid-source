# RE-004: sentinel-gate family (node #94)

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94,
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Worktree baseline: HEAD 2993e46 (upstream sync forbidden for this run)
- Source commit / reference commit: n/a — no reference-tree claim is made
- Claim status: observation for the census (46 FDEs, 47 gates, byte-anchored),
  the gate idiom, the offset classes, the branch polarities, the vectors-zero
  rejoin shape (23 gates), the double-gate chain, the counter-coupled gates,
  and the flag anchor; inference for the routing model (faithful translation
  of the instruction streams) and for the producer conclusion (no constructor
  in the examined code); unresolved items are listed under Results and
  limitations
- Scope included: all 47 sentinel gates in the binary; the three offset
  classes; the branch polarities; the vectors-zero rejoin shape; the
  double-gate function 0x4e852a0; the four counter-coupled gates; the
  flag-anchor function 0x3272190; the two boolean (setne) gates; and the
  four-prong producer negative search
- Scope excluded: the decoder bodies (0x2787460, 0x2786dd0), the transform
  and cleanup callee bodies, the twin functions' own behavior (previously
  mapped — see Prior work), gate functions' callees in general, the wider
  purpose of the tagged-value family, whether matching vectors ever occur
  in real executions, and node #115

## Reproduce

Platform: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (`-d -M intel`).
Run from the repository root. The binary is read and disassembled, never executed.

```
python3 tools/artifacts.py verify
python3 tools/sentinel_gate_family94.py --out research/work-items/RE-004-sentinel-gate-family-94
python3 -m unittest discover -s tests -p 'test_sentinel_gate_family94.py'
(cd research/work-items/RE-004-sentinel-gate-family-94 && sha256sum -c MANIFEST.sha256)
objdump -d -M intel --start-address=0x4e852a0 --stop-address=0x4e85420 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x3272190 --stop-address=0x3272280 artifacts/node/94/hl-node
```

The tool checks the input SHA-256 first and fails on a mismatch. It takes
about 20 seconds (the disp32 census scan walks .text). Outputs:
`evidence.json`, `gates.tsv`, `cases.tsv` and `windows.txt`. The census
derivation itself uses no disassembler: it is a byte-level disp32 scan
plus pcmpeqb-prefix checks. The feed classification and the post-gate
shapes were derived with a capstone 5.0.7 linear sweep inside FDE bounds
and are pinned by the recorded anchor bytes and FDE digests, so they are
re-checkable without trusting the sweep.

## Evidence

Coordinates are ELF virtual addresses. The #164 tag-5 resolver twins
compared an object's [0x68..0x88] vectors against two fixed 16-byte
constants. That gate is not twin-specific: it appears 47 times in 46
functions across the binary.

**Constants (observation).** The high constant at `0x204be0` is
`e500b653ca82273b7bfad8045d85a470` and the low constant at `0x206160`
is `c5d2460186f7233c927e7db2dcc703c0`. They are arbitrary 16-byte
patterns (not zeros, not ones).

**The idiom (observation, byte-anchored in all 47 gates).** Two movdqu
loads feed xmm0/xmm1, then two pcmpeqb compares against the constants
(66 0f 74 with a rip-relative disp32), then pand, then pmovmskb, then
cmp against 0xffff, then a conditional branch or setne. The two compares
are usually adjacent instructions, but some gates interleave a feed
between them (for example 0x279d5e0: load-compare-load-compare), so the
census pairs consecutive compares per FDE in address order rather than
assuming adjacency.

**Census (observation).** A byte-level disp32 scan over all of .text
finds exactly 94 rip-relative references to the two constants, and an
independent capstone sweep inside FDE bounds finds the same 94
instructions (94/94 agreement, zero uncovered candidates). Every one is
a pcmpeqb. Grouped by FDE: 46 functions, 47 gates (0x4e852a0 holds two).

| Class | Compared offsets | Gates | Functions | Branch polarity |
| --- | --- | --- | --- | --- |
| A | +0x68 / +0x78 | 42 | 41 | 36 je, 6 jne |
| B | +0x00 / +0x10 | 3 | 3 | 3 jne |
| C | +0x20 / +0x30 | 2 | 2 | 2 setne |
| Total | | 47 | 46 | 36 je, 9 jne, 2 setne |

Class A is the twins' layout (the tagged-object vectors). Classes B and
C compare a 32-byte value at a different base offset against the same
two constants; the packet claims only the observed offsets, not that
these are the same object type. `gates.tsv` lists every gate with its
FDE, class, compare addresses, branch address and polarity, feed
displacements, and feed base registers.

**Prior work (attribution, not re-claim).** Two of the 46 FDEs are the
#164 twins (0x2788350, 0x2788500, PR #1785). They are census members
here; their behavior is not re-claimed. One more address note: 0x279d5e0
starts exactly where the #161 caller-B window ends
(0x279d3e0..0x279d5e0); half-open windows share no byte, so this is
adjacency, not overlap.

**Vectors-zero rejoin (observation, 23 je gates).** In 23 of the 36 je
gates, the non-match fall-through OR-folds the compared vectors and
branches away (jne) if any vector qword is nonzero; if all vector qwords
are zero, control falls through to the je target's block, which OR-folds
the difference field. In other words, for these gates a non-match with
all-zero vectors is treated exactly like a match for routing purposes.
The 23 gates are: 0x1ebde00, 0x1ebe3e0, 0x1ebe9c0, 0x1ebec00, 0x1ebfe60,
0x1ec0150, 0x279d5e0, 0x279dbf0, 0x32aabb0, 0x32ab270, 0x32ab3d0,
0x32b4630, 0x32d0920, 0x32d0f30, 0x32d1540, 0x32fe000, 0x32ff750,
0x44c07a0, 0x44c98e0, 0x44c9ec0, 0x44ca770, 0x4e84cc0, and gate 1 of
0x4e852a0. Each one's jne anchor is byte-verified by the generator.
The other 13 je gates have different non-match continuations (including
the twins' transform paths).

**Double-gate chain (observation, 0x4e852a0).** This function holds two
gates on the same object (r14). Gate 0 is the twin pattern: decode
(0x4e84500) → tag == 5 → header == 4 → sentinel gate → match path
(adopt, [r14] = 1 plus decoded copy) or transform path (overwrite
[r14+0x0..0x40]). Gate 1 runs afterwards only when the input's flag byte
([rdi+0xb0], read at entry into r15b) exceeds 4. Gate 1 re-tests the
same vectors and is itself one of the 23 rejoin gates: on a match, or on
vectors all zero, control reaches the difference check, which OR-folds
[r14+0x40..0x58] (the #161 difference field) and jumps to 0x4e855e8 when
the difference is all zero. At 0x4e855e8 the counter [r14+0x60] is
compared against 0 and the result becomes the flag output (sete r15b).
So in this one function the sentinel vectors, the difference field, and
the counter field form a single decision chain. Gate 0's transform does
not touch [r14+0x68..0x88], so gate 1 re-reads unchanged vectors.

**Counter-coupled gates (observation, 4 jne gates).** In 0x2787ca0,
0x32ab530, 0x4dd6580 and 0x4e6f840, the match path (fall-through after
jne) immediately tests [r15+0x60] == 0 (bytes 49 83 7f 60 00 in all four)
and branches again (je). The packet claims only the observed test, not
that r15 is the same object as the gate's compared base.

**Flag anchor (observation, 0x3272190, the smallest gate FDE at 226
bytes).** This function gates on stack slots [rsp+0x68]/[rsp+0x78] with
the same idiom and materializes the outcome as a byte flag: match
(je 0x3272203) → dl = 0, non-match → dl = 1, stored at [rbx+0x28].

**Boolean gates (observation, class C).** 0x326cfc0 and 0x326d240 do not
branch on the gate at all: after cmp 0xffff they use setne, producing a
0/1 value (match → 0, non-match → 1) that feeds later arithmetic.

**Producer negative (observation, four prongs).** Nothing in the
binary's code constructs the sentinel vectors:
1. No instruction in .text references either constant except the 94
   pcmpeqb compares (disp32 scan and capstone sweep agree 94/94).
2. Neither 16-byte constant pattern occurs anywhere in .text, so no
   function builds the vectors from immediates.
3. No 8-byte little-endian pointer to either constant exists in any
   non-executable section, so no data indirection reaches them.
4. No gate function writes the compared vectors inline: a full
   instruction-level sweep finds zero stores to +0x68/+0x78 (or the
   class B/C offsets) inside the 46 gate FDEs, except two stores in
   0x4e856f0 to stack slots [rsp+0x68]/[rsp+0x78], which are not object
   writes (no movdqu store exists in any gate FDE).

## Inferences

- **The match path's liveness cannot be established from this binary's
  code alone.** Because no examined code constructs a matching vector,
  a match can only occur if the vectors arrive with the object from
  outside the examined code: deserialized or forwarded state, or a
  callee outside the examined set. This answers the #164 next question
  ("is the match path live?") honestly: not provable live from code.
- **Vectors-zero is a third outcome, not a bug.** In 23 gates the code
  treats "vectors all zero" exactly like "vectors match" for routing.
  The natural reading is a three-way classification (match / empty /
  live), with empty folded into match. This is an inference from the
  control flow, not a semantic proof.
- **The sentinel gate, the difference field, and the counter field
  belong to one decision family.** The double-gate chain tests all
  three in sequence, and four more gates test the counter on the match
  path. The packet does not claim the #162 open question (whether any
  later reader treats a stored 0 as "no change") is answered: the
  difference checks observed here test all-zero vs nonzero, which is
  consistent with, but does not by itself prove, a "no change" reading.
- **Classes B and C are the same test on different layouts.** They
  compare a 32-byte value against the same constants with the same
  idiom, so the sentinel test is layout-independent; whether they are
  the same object type is unresolved.

## Results and limitations

- The routing model is a faithful translation of the instruction
  streams, verified anchor by anchor; it is not an execution of the
  node binary, which this task forbids.
- Gate functions' callees are out of scope: a callee could in principle
  write the compared vectors. The examined exceptions are the twins'
  transform/match callees, which write [r14+0x0..0x40] and
  [r14+0x8..0x38] respectively, not the vectors.
- FDE bounds are unwind-described ranges, not validated function
  boundaries. Windows are pinned by full-FDE digests, so any additional
  code in a window would break regeneration.
- Object identity across registers is not established: the packet
  reports observed base registers and offsets, and does not equate
  r15 with a gate's compared base in the counter-coupled gates, nor
  rdi's flag byte with the decoded object's flag in the double-gate
  function.
- The 13 non-rejoin je gates' non-match continuations are not modeled
  beyond their polarity (they include transform paths like the twins').
- Out of scope by precondition, not by oversight: decoder bodies,
  transform and cleanup callee bodies, the wider purpose of the
  tagged-value family, whether matching vectors ever occur in real
  executions, and node #115.

## Next question

- Who populates [obj+0x68..0x88] before the first gate runs — which
  deserialization or forwarding path writes the vectors, and does any
  real execution ever present the sentinel constants themselves?
- What do the 13 non-rejoin je gates do on their non-match paths, and
  do any of them distinguish "vectors all zero" from "vectors match"
  the way the 23 rejoin gates do not?
