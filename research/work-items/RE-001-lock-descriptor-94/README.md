# RE-001: bind the node #94 lock-guard cell 0x5786278 and its family

- Component: `foundation`; bounded static validation under RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Claim status: byte/record observations; the once-style guarded-cell label is
  inferred from the state word, the cmpxchg sequences and the two-guard
  partition; no reconstruction, no gate request.
- Scope included: the 0x40-byte `.data` cell at `0x5786278` (two
  relocation-bound slots at +0x00 and +0x28, state word 3 at +0x20), the
  18-byte zeroing glue `0x35ab620..0x35ab632` (FDE `0xe3586c`), the 180-byte
  accessor `0x3790fc0..0x3791074` (FDE `0x11a7fd0`, constant index `0xaf93b`,
  three GOT-mediated callees), the 353-byte sibling guard
  `0x358db60..0x358dcc1` (FDE `0x1187d78`, six cell references, four
  `lock cmpxchg` sites, the 1e9-nanosecond park timeout, six GOT-mediated
  callees), and the whole-`.text` census including the twelve cell lea
  references.
- Scope excluded: the 952-site helper body `0x358dcd0..0x358de41` (bound in
  `readlock-helper-94`; its six cell references are re-verified here as
  cross-links), the lookup callee `0x151f6f0`, the once machinery
  `0x4ee3b20`, both unpark paths, #115, visor.

## Question

The read-lock helper packet left its descriptor cell unbound: what does the
cell at `0x5786278` hold, and which guards reach it?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`.

```sh
python3 tools/lock_descriptor_static.py --output work/lockcell-record.json
diff work/lockcell-record.json research/work-items/RE-001-lock-descriptor-94/observed/records.json
python3 -m unittest discover -s tests -p test_lock_descriptor_static.py -v
```

The tool authenticates size and SHA-256, then checks the exact cell bytes,
both slot relocations and the state word; the exact bodies and FDE records of
all three bound functions; the glue's zeroing structure; the accessor's
constant index, three call sites against relocations, and the ud2-terminated
error path; the sibling's anchors, four cmpxchg sites, six cell lea
references and six call sites; the census (zero code references for the glue
and accessor, three sibling call sites each inside its caller FDE, and the
twelve-way cell lea partition). Disassembly text in `observed/` was rendered
with capstone 5.0.7 and labeled as such; byte records are authoritative.
Platform: Windows 10 22H2, Python 3.11.9.

## Observations

The cell `0x5786278` (`.data`, 0x40 bytes bound) carries exactly two
relocation-bound code pointers — the glue `0x35ab620` at +0x00 and the
accessor `0x3790fc0` at +0x28 — plus the state word 3 at +0x20 and zero
padding elsewhere. Both pointers are unreachable from code: across the
complete `.text` census the glue and accessor receive zero `e8` direct calls,
zero `ff 15` GOT-mediated calls and zero `lea` references; the only paths to
them run through the cell's slots. Exactly twelve `lea` instructions target
the cell: six inside the sibling guard and six inside the 952-site helper
(`0x358dcd0..0x358de41`, separate packet).

The glue returns its argument after zeroing 24 bytes at `[rdi]` — an
observed clear-on-drop shape. The accessor zeroes a 48-byte stack result,
calls the chrono-adjacent lookup `0x151f6f0` through GOT slot `0x576e890`
with the constant index `0xaf93b` (719163), copies the result on success and
otherwise reaches `ud2` through the display panic `0x157a9f0`.

The sibling guard mirrors the 952-site helper at a different scale: it claims
the cell state with `lock cmpxchg` (four sites, expected value 0, new value
8), parks with the shared `0x3b9aca00` (1e9-nanosecond) timeout through the
same `0x4e0d2c0` parking wrapper the helper uses (twice here), consults the
once machinery `0x4ee3b20` with the force flag 1, and routes two panics
through `0x157b480` and `0x157b63b`. Called through GOT slot `0x5773e18`
from exactly three sites, each inside a distinct FDE
(`0x2355f40..0x235e836`, `0x4caa870..0x4cb31f6`, `0x4cb3200..0x4cbbb86`),
with zero direct references.

## Implementation and comparison

Not implemented: no reconstructed Rust, no two-build comparison.

## Results and limitations

- 1 cell (0x40 bytes), 3 bodies (18 + 180 + 353 bytes), 3 FDE records, 2
  slot relocations, 4 anchor immediates, 9 GOT-mediated call sites across the
  three bodies, 4 cmpxchg sites, 12 cell lea references; census denominator
  is the complete `.text` for `e8` / `ff 15` / `lea` encodings.
- 8 tests pass (record match, cell layout, glue structure, accessor constant
  and lookup, sibling census and caller FDEs, lea partition, body/cell/
  relocation mutation controls). Author rerun, not independent peer review.
- Unknowns: what the constant index 719163 selects in the lookup, what the
  48-byte value represents, and which of the three sibling caller families
  guards what. The once-style label stays inferred. No execution, Rust build,
  hosted CI, or gate.

Next question: the lookup callee `0x151f6f0` behind the accessor's constant
index, and the once machinery `0x4ee3b20` shared by both guards.
