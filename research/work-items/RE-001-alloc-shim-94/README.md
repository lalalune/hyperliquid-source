# RE-001: bind the node #94 RawVec allocator shim 0x454f420

- Component: `foundation`; bounded static function validation under RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Claim status: byte/record observations plus the aligned-bytes identity; the
  RawVec label is inferred; no reconstruction, no gate request.
- Scope included: the 234-byte body `0x454f420..0x454f50a` (FDE `0xedb6d4`),
  eleven anchors, four allocator dispatch sites with relocation targets, the
  aligned-capacity identity, and the whole-`.text` census.
- Scope excluded: the growth helper (bound in `RE-001-crossroads-callees-94`),
  the four allocator entry points, the 253 caller families, #115, visor.

## Question

The growth helper called an allocator directly: what does `0x454f420` compute,
and how widely is it shared?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`.

```sh
python3 tools/alloc_shim_static.py --output work/alloc-record.json
diff work/alloc-record.json research/work-items/RE-001-alloc-shim-94/observed/records.json
python3 -m unittest discover -s tests -p test_alloc_shim_static.py -v
```

The tool authenticates size and SHA-256, then checks the exact body and FDE,
eleven anchors (the align+capacity-1 lea, the aligned mask, the size
multiply with its overflow flag, the i64::MIN bound constant, the overflow
error code 8, the alignment-16 threshold, both tzcnt checks, the success code
16 and the flag clear), the four dispatch sites against relocations, the
aligned-bytes identity, and the census. Disassembly text in `observed/` was
rendered with capstone 5.0.7 and labeled as such; byte records are
authoritative. Platform: Windows 10 22H2, Python 3.11.9.

## Observations

The body computes the aligned byte count: `(align + capacity - 1) & -align`
multiplied by the element size, guarded by a multiply-overflow flag and a
comparison against `0x8000000000000000 - align` (identity validated on a
powers-of-two x capacity x size grid). Allocation selects one of four entry
points: a null old-pointer branches between grow (`0x54c5620`, or the aligned
`0x54c5610` past the alignment-16 threshold and a tzcnt power-of-two check)
and free-or-alloc paths (`0x54c2670`, `0x54c06b0`). The result stores the
pointer at a flag-dependent offset and returns error code 8 on overflow,
16 on success. Called directly from 253 sites with zero GOT-mediated and
zero `lea` references; the growth helper's site `0x454e5e5` is among them.

## Implementation and comparison

Not implemented: no reconstructed Rust, no two-build comparison.

## Results and limitations

- 1 body (234 bytes) + FDE, 11 anchors, 4 dispatch sites against
  relocations, 1 identity grid; census denominator is the complete `.text`
  for `e8` / `ff 15` / `lea` encodings.
- 6 tests pass (record match, identity, dispatch, census, error codes, body
  mutation control). Author rerun, not independent peer review.
- Unknowns: the four allocator entry points' internals and what the 253
  caller families allocate. The RawVec label stays inferred. No execution,
  Rust build, hosted CI, or gate.

Next question: the allocator entry points behind the four GOT slots and the
lazy-cell initializer `0x143ef30`.
