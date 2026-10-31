# RE-001: bind the node #94 crossroads small callees 0x14385c0 and 0x454e5b0

- Component: `foundation`; bounded static function validation under RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Claim status: byte/record observations plus the capacity-selection identity;
  the lazy-getter and growth labels are inferred; no reconstruction, no gate
  request.
- Scope included: the 107-byte lazy getter `0x14385c0..0x143862b` (FDE
  `0xceadd4`) with its `.data` cell at `0x577ab80` (initializer relocation,
  ship-complete state 3, zero value words, once companion) and the std
  `sync/once.rs:219:20` Location; the 100-byte capacity growth helper
  `0x454e5b0..0x454e614` (FDE `0xedb128`) with its allocator call, element
  size, minimum capacity and observed constant; both censuses.
- Scope excluded: the crossroads body (bound in `RE-001-crossroads-body-94`),
  the Once state machine (`RE-001-once-state-94`), the initializer
  `0x143ef30`, the allocator `0x454f420`, the error target `0x1346068`, #115,
  visor.

## Question

The crossroads body called two small helpers besides the series anchors: what
are `0x14385c0` and `0x454e5b0`?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`.

```sh
python3 tools/crossroads_callees_static.py --output work/callees-record.json
diff work/callees-record.json research/work-items/RE-001-crossroads-callees-94/observed/records.json
python3 -m unittest discover -s tests -p test_crossroads_callees_static.py -v
```

The tool authenticates size and SHA-256, then checks both exact bodies and
FDE records, eighteen anchors, the cell facts (initializer relocation, state
byte, zero value), the std once Location struct, both call targets against
relocations, the capacity-selection identity, and both censuses.
Disassembly text in `observed/` was rendered with capstone 5.0.7 and labeled
as such; byte records are authoritative. Platform: Windows 10 22H2,
Python 3.11.9.

## Observations

The lazy getter `0x14385c0` reads a state dword at `0x577ab98`; when nonzero
it returns the two value words at `0x577ab88`/`0x577ab90` directly, and
otherwise drives the std Once state machine (`0x4ee3b20`) with force flag 1,
passing the initializer `0x143ef30` (bound into the cell's first word by
relocation), the companion struct at `0x5669f68` and the std
`sync/once.rs:219:20` Location. The cell ships in the file image with state 3
(the Once complete state) and two zero value words — a ship-complete lazy
cell whose cold path exists for completeness. Called through GOT slot
`0x576f488` from 87 sites with zero direct or `lea` references.

The growth helper `0x454e5b0` reads the current capacity, doubles it, and
selects `max(2 * current, 4)` through a `cmovae` (identity validated);
multiplies by the element size 8, passes the observed constant `0x168` and
calls the allocator `0x454f420` directly; on success stores the new capacity
and pointer, otherwise routes through GOT slot `0x576dfb8` to `0x1346068`.
Called from 8 GOT-mediated sites with zero direct or `lea` references.

## Implementation and comparison

Not implemented: no reconstructed Rust, no two-build comparison.

## Results and limitations

- 2 bodies (107 + 100 bytes) + FDEs, 18 anchors, 1 cell with relocation and
  state facts, 1 Location struct, 2 call targets against relocations, 1
  capacity identity; census denominator is the complete `.text` for
  `e8` / `ff 15` / `lea` encodings.
- 6 tests pass (record match, ship-complete cell, capacity identity, sizes
  and censuses, body and cell-state mutation controls). Author rerun, not
  independent peer review.
- Unknowns: what the getter's value words represent and what the initializer
  would compute; what the constant `0x168` selects in the allocator. Labels
  stay inferred. No execution, Rust build, hosted CI, or gate.

Next question: the initializer `0x143ef30`, the allocator `0x454f420`, and
the two large crossroads callees `0x143d010` and `0x4b31e70`.
