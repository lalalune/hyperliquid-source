# RE-001: bind the node #94 statistics body at 0x4898810

- Component: `foundation`; bounded static function validation under RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Claim status: byte/record observations; the "statistics body" label is
  inherited from the window-guard packet's census note; no reconstruction,
  no gate request.
- Scope included: the FDE-bounded body `0x4898810..0x489a544` (7,476
  bytes), its FDE record, all 240 verified branch destinations, all 12
  direct `e8` call sites with destinations (including both calls of the
  ema window-guard body `0x474fb90` at exactly the two sites that packet's
  census bound), all 37 GOT-mediated call sites with their slots (through
  which the chrono NaiveTime helper `0x15206e0` and the Time Sub helper
  `0x1447130` are each reached once), twelve panic Locations — eight
  distinct std BTreeMap internals plus chrono `naive/datetime/mod.rs
  1631:38`, whose Location struct VA `0x566af18` is the exact one the
  window-guard packet binds — and the two-site direct-call census. Scope
  excluded: the window guard, both chrono shift helpers and their Sub
  wrapper, the Time Sub helper, the ema update body, the small caller
  wrapper `0x474f8a0..0x474fa44`, #115, visor.

## Question

The window-guard packet bound the guard and named its containing function
`0x4898810..0x489a550` as the next target; what does that body carry?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`.

```sh
python3 tools/statistics_body_static.py --output work/stats-record.json
diff work/stats-record.json research/work-items/RE-001-statistics-body-94/observed/records.json
python3 -m unittest discover -s tests -p test_statistics_body_static.py -v
```

The tool authenticates size and SHA-256, then checks the exact FDE record
and body bytes, every branch destination, every direct and indirect call
site with its destination or GOT slot, the chrono and Time Sub GOT
relocations, the twelve Location structs through their relocations, and
the whole-`.text` census for `e8` and `lea` encodings. The tool source's
constant tables were emitted mechanically from the authenticated binary by
a one-shot generator kept out of the packet. Disassembly text in
`observed/` was rendered with capstone 5.0.7 and labeled as such; byte
records are authoritative. Platform: Windows 10 22H2, Python 3.11.9.

## Observations

Called directly (`e8`) from exactly two sites — `0x474f9c0` and
`0x474fa28` — both inside the small wrapper `0x474f8a0..0x474fa44` that
sits immediately before the guard in address order; zero `lea`
references; no GOT slot of its own.

The body calls the window guard `0x474fb90` from `0x4899415` and
`0x4899910` — the exact two sites that packet's census recorded as the
guard's only callers — and reaches the chrono NaiveTime shift helper
(`0x576e8a8` → `0x15206e0`, bound in the chrono-shift packet) and the
Time Sub helper (`0x576e8c0` → `0x1447130`, the 72-site helper bound in
the Time Sub packet) once each through their GOT slots. Eleven other
distinct GOT slots carry the remaining 35 indirect calls, dominated by
panic machinery (`0x157a9f0` panic_display ×9, `0x157b63b` ×4,
`0x157b7f0` ×2).

Twelve panic Locations: std BTreeMap internals —
`collections/btree/navigate.rs` 161:36, 198:39, 534:47, 600:48;
`collections/btree/node.rs` 618:9, 670:9; `collections/btree/map.rs`
306:46; `collections/btree/map/entry.rs` 614:42 — plus chrono
`naive/datetime/mod.rs:1631:38` at Location struct VA `0x566af18`, the
same struct the window guard's own overflow panic uses. The BTreeMap set
matches the context-structure accesses the window-guard packet observed
(window timestamp at `context +0x28`), now with the std source anchors.

## Implementation and comparison

Not yet implemented: no reconstructed Rust, no two-build comparison, no
semantic claim about what the body computes.

## Results and limitations

- 1 body bound to the digest (7,476 bytes), 1 FDE record, 240 branch
  destinations, 12 direct call sites, 37 GOT-mediated call sites, 12
  chrono/std panic Locations, 2 helper GOT relocations; census
  denominators are the complete `.text` for `e8` and `lea` encodings.
- 11 tests pass (retained record, FDE/body identity with table shapes,
  guard call anchor, helper GOT anchors, Location anchors, size/SHA
  rejection, body/FDE mutation controls, Location mutation controls, GOT
  mutation controls, census). Author rerun, not independent peer review.
- Unknowns: the body's actual computation, the eleven unbound GOT slot
  targets, and the wrapper's role. No execution, Rust build, hosted CI,
  or gate.

Next question: the eleven unbound GOT targets, starting with the
`0x576e010` slot (×10, the body's most-used helper).
