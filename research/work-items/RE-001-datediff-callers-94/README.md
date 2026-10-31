# RE-001: bind the node #94 date-difference callers 0x1450a60 and 0x13cec80's site

- Component: `foundation`; bounded static function validation under RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Claim status: byte/record observations plus the decoded divide-by-1000
  identity; the float-seconds wrapper label is inferred from the constants
  and the datediff cross-link; no reconstruction, no gate request.
- Scope included: the 115-byte wrapper `0x1450a60..0x1450ad3` (FDE
  `0xcec23c`, eight byte anchors, the datediff GOT call, two rip-relative
  double loads), the FDE record of the 7186-byte body
  `0x13cec80..0x13d0892` and its datediff call site at `+0x1141`, the
  shared 1e6 double at `0x20ae60`, the absolute-value mask at `0x202ed0`,
  and the whole-`.text` census of both callers.
- Scope excluded: the datediff core `0x151d1b0` and its leap table (bound in
  `RE-001-datediff-chrono-94`), the shared Time Sub helper (bound in #63),
  the remaining 7185 bytes of the giant body, the two caller families, #115,
  visor.

## Question

The datediff packet censused three GOT-mediated callers; one is the Time Sub
helper itself. What are the other two?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`.

```sh
python3 tools/datediff_callers_static.py --output work/callers-record.json
diff work/callers-record.json research/work-items/RE-001-datediff-callers-94/observed/records.json
python3 -m unittest discover -s tests -p test_datediff_callers_static.py -v
```

The tool authenticates size and SHA-256, then checks the exact wrapper body
and FDE, eight byte anchors (the push slot, the datediff call, the 1e6 and
1e9 immediates, the `0x10624dd3` magic with shift 38, both double loads), the
datediff GOT slot against relocations, the shared 1e6 double and mask values,
the giant's FDE record and call-site bytes, and the census. Disassembly text
in `observed/` was rendered with capstone 5.0.7 and labeled as such; byte
records are authoritative. Platform: Windows 10 22H2, Python 3.11.9.

## Observations

The wrapper `0x1450a60..0x1450ad3` opens by calling the datediff core
through GOT slot `0x576eaa0` with the two packed dates already in the
argument registers, takes the `(i64 seconds, i32 nanos)` result, computes the
borrow flag (seconds < 0 and nanos > 0), adjusts both parts — seconds gain
the borrow, nanos lose `0x3b9aca00` — scales seconds by `0xf4240` (1e6),
divides the adjusted nanos by 1000 through the `0x10624dd3` magic with shift
38 plus a sign fix (proved a truncating division on the signed nanosecond
domain), sums the parts under two `seto`/`jne` overflow guards that skip the
conversion, converts to double, divides by the shared 1e6 double at
`0x20ae60`, and masks with the absolute-value constant pair at `0x202ed0`.
Inferred label: a date difference rendered as absolute float seconds. Called
through GOT slot `0x576f6c8` from exactly one site (`0x44ab1b2`, inside FDE
`0x44aa5a0..0x44ab55b`), with zero direct or `lea` references.

The other caller site `0x13cfdc1` sits at offset `+0x1141` of the 7186-byte
FDE body `0x13cec80..0x13d0892`; its six call bytes resolve to the same
datediff GOT slot. The giant is itself called through GOT slot `0x576ea80`
from exactly one site (`0x1400e4f`, inside FDE `0x1400d80..0x1400e8d`). The
giant's body stays out of scope.

## Implementation and comparison

Not implemented: no reconstructed Rust, no two-build comparison. The
divide-by-1000 identity is a Python validation of decoded arithmetic, not
target equivalence.

## Results and limitations

- 1 wrapper body (115 bytes) + FDE, 8 anchors, 2 rip-relative doubles, 1
  giant FDE + call site, 2 GOT-mediated caller censuses; denominator is the
  complete `.text` for `e8` / `ff 15` / `lea` encodings.
- 8 tests pass (record match, anchors, shared anchors, trunc-division grid,
  giant scope, census, body and call-site mutation controls). Author rerun,
  not independent peer review.
- Unknowns: what the two caller families compute and why one path wants
  absolute float seconds. The label stays inferred. No execution, Rust build,
  hosted CI, or gate.

Next question: the wrapper's caller family inside `0x44aa5a0..0x44ab55b` and
the giant body `0x13cec80..0x13d0892` itself.
