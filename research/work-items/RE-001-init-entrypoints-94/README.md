# RE-001: bind the node #94 initializer entry points 0x4edce70 and 0x4f100b0

- Component: `foundation`; bounded static function validation under RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Claim status: byte/record observations plus two small identities; the
  argument-processor and iterator labels are inferred; no reconstruction, no
  gate request.
- Scope included: the 472-byte body `0x4edce70..0x4edd048` (FDE `0x12f64d0`)
  and the 214-byte body `0x4f100b0..0x4f10186` (FDE `0x12f7f7c`), eighteen
  anchors, ten relocation-checked call sites, the capacity-bound and stride
  identities, the relocation-free imported slots, and both censuses.
- Scope excluded: the build-mode initializer (bound in
  `RE-001-build-mode-init-94`), the alloc/dealloc/error entry points
  (`RE-001-alloc-shim-94`), the next-stage callee `0x4f04bb0`, the iterator
  and panic_fmt callees, #115, visor.

## Question

The build-mode initializer opens with two calls before parsing: what do its
entry points `0x4edce70` and `0x4f100b0` do?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`.

```sh
python3 tools/init_entrypoints_static.py --output work/iep-record.json
diff work/iep-record.json research/work-items/RE-001-init-entrypoints-94/observed/records.json
python3 -m unittest discover -s tests -p test_init_entrypoints_static.py -v
```

The tool authenticates size and SHA-256, then checks both exact bodies and
FDE records, eighteen anchors (the bound constant, the shared entry-point
calls, both ud2 terminators, the i64::MIN sentinel, the 0x18 stride, the
error operands), ten call sites against relocations, the two identities, the
relocation-free imported slots, and both censuses. Disassembly text in
`observed/` was rendered with capstone 5.0.7 and labeled as such; byte
records are authoritative. Platform: Windows 10 22H2, Python 3.11.9.

## Observations

The first entry point reads two `.bss` globals (`0x5788550`, `0x5788548`),
bounds a count against `0x0555555555555555` — exactly `(2^64 - 1) / 3`, the
maximum element count whose tripled byte size cannot overflow — and drives
the shared alloc/dealloc/error entry points plus two imported slots
(`0x576e038`, `0x576dfe0`) that carry no static relocations, with a
ud2-terminated error block. The second advances a `0x18`-stride (three
qwords) iterator against an i64::MIN sentinel, routes a formatted failure
through panic_fmt with a 43-byte operand to ud2, and deallocates through the
shared entry point. Each is called from exactly three GOT-mediated sites
(the initializer's own two calls among them), with zero direct or `lea`
references.

## Implementation and comparison

Not implemented: no reconstructed Rust, no two-build comparison.

## Results and limitations

- 2 bodies (472 + 214 bytes) + FDEs, 18 anchors, 10 relocation-checked
  calls, 2 identities; census denominator is the complete `.text` for
  `e8` / `ff 15` / `lea` encodings.
- 7 tests pass (record match, both identities, censuses, shared entry
  points, imported slots, body mutation controls). Author rerun, not
  independent peer review.
- Unknowns: what the two globals hold at runtime, the imported slots'
  runtime targets, and the iterated element semantics. Labels stay
  inferred. No execution, Rust build, hosted CI, or gate.

Next question: the next-stage callee `0x4f04bb0` and the two large
crossroads callees `0x143d010` / `0x4b31e70`.
