# RE-004: non-rejoin sentinel-gate paths (node #94)

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94,
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Worktree baseline: HEAD 2993e46 (upstream sync forbidden for this run)
- Source commit / reference commit: n/a — no reference-tree claim is made
- Claim status: observation for the gate census cross-check (47 gates,
  46 FDEs, byte-anchored), the 13-gate partition, the 9 fall-through
  segments, and the install ranges; inference for the routing model
  (faithful translation of the instruction streams) and for the
  vectors-zero conclusion (no non-rejoin path re-tests the vectors);
  unresolved items are listed under Results and limitations
- Scope included: all 13 non-rejoin je gates from #165; the 9
  fall-through segments of the newly examined gates; the same-callee
  trio's both-path callee equality; the twin-B clones' similarity
  measurement; the twin-shape pair's classification; the partition
  arithmetic (3 + 4 + 2 + 4 = 13)
- Scope excluded: the 23 rejoin gates' internals (mapped in #165); the
  twins' own behavior (PR #1785); gate 0 of 0x4e852a0 (#165); the flag
  anchor's body (#165); decoder bodies; transform and cleanup callee
  bodies; the 0x4e6bcb0 tag-5 prelude (see Limitations); the wider
  purpose of the tagged-value family; whether matching vectors ever
  occur in real executions; and node #115

## Reproduce

Platform: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (`-d -M intel`).
Run from the repository root. The binary is read and disassembled, never executed.

```
python3 tools/artifacts.py verify
python3 tools/non_rejoin_gate_paths94.py --out research/work-items/RE-004-non-rejoin-gate-paths-94
python3 -m unittest discover -s tests -p 'test_non_rejoin_gate_paths94.py'
(cd research/work-items/RE-004-non-rejoin-gate-paths-94 && sha256sum -c MANIFEST.sha256)
objdump -d -M intel --start-address=0x4e6fd50 --stop-address=0x4e6fe02 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x4e85764 --stop-address=0x4e857b3 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x4e6bf86 --stop-address=0x4e6bfc7 artifacts/node/94/hl-node
```

The tool checks the input SHA-256 first and fails on a mismatch. It takes
about 20 seconds (the disp32 census scan walks .text). Outputs:
`evidence.json`, `paths.tsv`, `segments.txt` and `cases.tsv`. The census
derivation itself uses no disassembler: it is a byte-level disp32 scan
plus branch-opcode reading. The fall-through shapes were read from
disassembly and are pinned by recorded anchor bytes and segment digests,
so they are re-checkable without trusting the reading.

## Evidence

Coordinates are ELF virtual addresses. The #165 packet mapped 47
sentinel gates and classified 23 je gates as vectors-zero rejoin gates,
leaving 13 je gates whose non-match paths were not modeled beyond their
polarity. This packet models those 13.

**Census cross-check (observation).** A byte-level disp32 scan over all
of .text finds exactly 94 rip-relative references to the two constants
(0x204be0 = e500b653ca82273b7bfad8045d85a470,
0x206160 = c5d2460186f7233c927e7db2dcc703c0), grouped by FDE into 47
gates in 46 functions with polarities je 36, jne 9, setne 2 and classes
A 42, B 3, C 2 — identical to #165's published census. The 13 gates in
this packet are a subset of the derived je gates, and 36 − 13 = 23
recovers #165's rejoin count exactly.

**Partition (observation).** The 13 non-rejoin je gates partition as:

| Class | Gates | Disposition |
| --- | --- | --- |
| same-callee trio | 3 | newly modeled in full |
| twin-B clones | 4 | measured instances, not new behavior |
| twin-shape pair | 2 | classified |
| attributed, already mapped | 4 | cited, not re-claimed |
| Total | 13 | |

**Same-callee trio (observation, newly modeled).** In 0x4e6fd50,
0x4e856f0 and 0x4e6bcb0, the match path and the non-match path call the
SAME second-stage callee and both install [obj] = 1; only the source
buffer differs:

| Function | Shared callee | Non-match install | Match install |
| --- | --- | --- | --- |
| 0x4e6fd50 | 0x4e6c8b0 | [r14+0x0..0x40] from [rsp+0x30..0x70], [rsp+0x30] = 1 | [r14+0x0..0x38] from decoded [rsp+0x0..0x30], [r14] = 1 |
| 0x4e856f0 | 0x4e81dc0 | [r14+0x0..0x40] from [rsp+0x70..0xb0], [rsp+0x70] = 1 | [r14+0x0..0x38] from decoded [rsp+0x20..0x50], [r14] = 1 |
| 0x4e6bcb0 | 0x4e6b5f0 | [rbp+0x0..0x40] from [rsp+0x30..0x70], [rsp+0x30] = 1 | [rbp+0x0..0x38] from decoded [rsp+0x30..0x60], [rbp] = 1 |

Both paths also call a cleanup callee on the object (0x4e6ed00,
0x4e84440, 0x4e6b870 respectively) when its header is not 4. Neither
path touches [obj+0x68..0x88]: the vectors are read only by the gate
itself. The non-match install is unconditional — it does not test
whether the vectors are zero, match, or anything else.

**Twin-B clones (observation, measured instances).** 0x32aca90,
0x32acca0, 0x44bb790 and 0x4dd6c90 are each 527 bytes with 93.4–94.5%
positional byte agreement with twin-B (0x2788500), and each uses
twin-B's exact transform pair on the non-match path: transform
0x37d13c0, then, when the transform output's first DWORD is 4, second
transform 0x324a070 plus [rsp+0x40] = 1, then installation of
[obj+0x0..0x40]. Only the decoder and cleanup callees differ. Because
they add no new behavior beyond twin-B's, they are reported here as
census instances supporting the partition, not claimed as new behavior;
template population of one packet per clone is explicitly declined.

**Twin-shape pair (observation, classified).** 0x1eb1cc0 and 0x1eb1e60
share the twins' skeleton (decode → tag == 5 → header == 4 → gate →
match adopt / transform install) but are not byte clones: positional
byte agreement with twin-A over the shared prefix is 28% and 26%
respectively. They share match callee 0x1e5f1c0 and cleanup 0x1eaffe0.
Their non-match transforms differ: 0x1eb1cc0 uses twin-A's transform
0x1e6af40, while 0x1eb1e60 uses twin-B's transform pair (0x37d13c0 +
0x324a070). Both install [r14+0x0..0x40] on the non-match path and
[r14+0x0..0x38] on the match path.

**Attributed gates (citation, not re-claim).** The twins 0x2788350 and
0x2788500 (PR #1785: match adopts, non-match transforms), gate 0 of
0x4e852a0 (#165: twin pattern), and the flag anchor 0x3272190 (#165:
match → dl = 0, non-match → dl = 1, stored at [rbx+0x28]) complete the
13. Their non-match paths are unconditional by their prior mappings.

**Vectors-zero negative (observation, 9 segments).** None of the 9
newly examined fall-through segments contains a second cmp 0xffff
(byte sequence `3d ff ff 00 00` occurs 0 times in each segment; the
gate's own cmp sits before the fall-through start). The fall-throughs
begin with a vector copy to the stack (twin-shape, twin-B clones) or a
same-callee call (trio) — never with a vector fold and zero branch.
Combined with the attributed 4, whose prior mappings are likewise
unconditional, the answer to #165's next question is: no non-rejoin
gate distinguishes vectors-all-zero from vectors-match.

**Claimed-anchor disjointness (observation).** Every recorded anchor in
this packet (segment bytes, call targets, one-stores, install stores)
lies strictly after its gate's branch instruction, while #165's
recorded anchors (feeds, compares, branch) lie at or before the branch.
The segments are sub-ranges of #165's FDE windows; that inclusion, this
disjointness, and #165's explicit next question inviting this follow-up
are disclosed here, following the #163 precedent for invited follow-ups.

## Inferences

- **Vectors-zero is visible only to the rejoin gates.** For the 13
  non-rejoin gates, a vectors-zero object takes exactly the non-match
  path: the transform output (twin-shape, clones), the flag value 1
  (flag anchor), or the callee's fresh output (trio). Empty never routes
  like match outside the 23 rejoin gates.
- **The same-callee trio collapses the gate to a buffer choice.** The
  gate does not select between "adopt" and "transform" here; it selects
  which buffer the shared callee fills, and both outcomes install
  [obj] = 1 with a full value. The sentinel test's only effect in these
  three functions is that choice.
- **The twin template is instantiated, not extended, by the clones.**
  Four further 527-byte functions reuse twin-B's transform pair
  verbatim; no new transform behavior appears in them.
- **The #162 stored-0 reader question is still not answered.** This
  packet shows non-rejoin paths never consult the difference field on
  the non-match path, but it does not show any later reader treating a
  stored 0 as "no change" — same status as #165.

## Results and limitations

- The routing model is a faithful translation of the instruction
  streams, verified anchor by anchor; it is not an execution of the
  node binary, which this task forbids.
- Segment bounds are defined per gate in the generator table:
  fall-through start (branch end) to the last install store's end
  (trio, twin-shape 0x1eb1cc0) or to the jump-to-install instruction's
  end (clones, twin-shape 0x1eb1e60). Install tails shared with other
  paths are recorded by anchor stores, not by contiguous segments.
- 0x4e6bcb0 is a 2960-byte function whose gate sits deep inside
  unrelated prelude logic. Its header check (cmp DWORD [rbp],0x4 at
  0x4e6bf53) and both paths are anchored, but its tag-5 prelude is not
  modeled; the packet claims only the gate and its two paths.
- 0x4e856f0's header check reads the decode return value (cmp rax,0x4
  at 0x4e8572b) rather than [r14], unlike the other trio members; the
  packet records the observed test without equating the two forms.
- Gate functions' callees are out of scope: a callee could in principle
  read the vectors, but no callee in the examined paths re-tests them
  against the sentinel constants (the callee call targets are recorded
  and none equals a gate address).
- FDE bounds are unwind-described ranges, not validated function
  boundaries. Segments are pinned by full-segment digests.
- Out of scope by precondition, not by oversight: decoder bodies,
  transform and cleanup callee bodies, the wider purpose of the
  tagged-value family, whether matching vectors ever occur in real
  executions, and node #115.

## Next question

- The same-callee trio's shared callees (0x4e6c8b0, 0x4e81dc0,
  0x4e6b5f0) take different output buffers on the two paths but are
  otherwise identical calls: what do they compute, and does their output
  depend on anything other than the buffer they are given?
- Who populates [obj+0x68..0x88] before the first gate runs — the
  remaining #165 next question, still open: no writer has been found in
  any gate FDE, and the writers, if any, live outside the gate set.
