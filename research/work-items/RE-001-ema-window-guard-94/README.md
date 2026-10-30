# RE-001: bind the node #94 ema window guard at 0x474fb90

- Component: `foundation`; bounded static function validation under RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Claim status: byte/record observations; the "window" label is inferred from
  the cascades and the chrono anchors; no reconstruction, no gate request.
- Scope included: the guard body `0x474fb90..0x474fce5` (341 bytes), its FDE
  record, both chrono-0.4.38 anchors (panic Location and the datetime range
  gate), the 86400-second day division, the three timestamp cascades, the
  forwarded f64 sample, the post-update copy, and the direct-call census.
  Scope excluded: callee semantics (`0x15206e0`, `0x151f870`), the ema update
  body (bound separately), the containing statistics function, #115, visor.

## Question

What guards the single call to the ema_tracker update body, and what
dependency evidence does the guard itself carry?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`.

```sh
python3 tools/window_guard_static.py --output work/guard-record.json
diff work/guard-record.json research/work-items/RE-001-ema-window-guard-94/observed/records.json
python3 -m unittest discover -s tests -p test_window_guard_static.py -v
```

The tool authenticates size and SHA-256, then checks the exact FDE record and
body bytes, eighteen verified branch destinations, both datetime range
constants, the day-division magic and shift, the callee argument constants,
four GOT-mediated call targets against relocations, the chrono panic message
and Location, the sample spill/reload pair, the window-base `lea`, and the
whole-`.text` census. Disassembly text in `observed/` was rendered with
capstone 5.0.7 and labeled as such; byte records are authoritative. Platform:
Windows 10 22H2, Python 3.11.9.

## Observations

Body `0x474fb90..0x474fce5` (341 bytes, FDE at `.eh_frame` VA `0xef91d0`,
sha256 `2b098dfa...`), called directly (`e8`) from exactly two sites —
`0x4899415` and `0x4899910` — both inside the FDE function
`0x4898810..0x489a550`, with zero `lea` references.

The guard carries two chrono-0.4.38 dependency anchors:

1. A panic whose Location is
   `chrono-0.4.38/src/naive/datetime/mod.rs:1631:38` with message
   `` `NaiveDateTime + TimeDelta` overflowed `` — the overflow panic of
   chrono's `NaiveDateTime + TimeDelta` implementation, reached when the
   first callee's result plus `0xffff574000000000` falls below
   `0xfffeae7ffffeae81` (chrono's representable datetime bounds).
2. The first callee's result is divided by 86400 (magic
   `0x1845c8a0ce512957`, shift 13+64) into whole days — proved as exact
   trunc division over a grid in the tool and tests — and the day count plus
   a context field feed the second callee.

Structure (observed): the incoming f64 sample is spilled at entry and
reloaded around the update call; three lexicographic three-dword timestamp
cascades run — sample vs the caller's window argument, sample vs the second
callee's result, and the stored window timestamp (`context +0x28`) vs the
sample; the update body `0x14791c0` (GOT slot `0x576f8f0`) is called only on
the falling-through path with the original `rdi` context and sample
timestamp; afterwards the 12-byte sample timestamp is copied to
`context +0x28`. The first callee receives the constant pair `(30, 0)`.

## Implementation and comparison

Not yet implemented: no reconstructed Rust, no two-build comparison. The
86400-division identity is a Python validation of decoded arithmetic, not
target equivalence.

## Results and limitations

- 1 guard body bound to digest (341 bytes), 1 FDE record, 18 branch
  destinations, 2 range constants, 1 magic divisor with identity grid, 4 GOT
  targets, 1 chrono panic Location; census denominator is the complete
  `.text` for `e8` / `lea` encodings.
- 9 tests pass (identity, FDE bounds, chrono anchor, day-division grid,
  body/FDE/message/Location/path/GOT-relocation mutation controls, census).
  Author rerun, not independent peer review.
- Unknowns: what the constant 30 selects in the first callee, both callees'
  semantics, and the containing statistics function's role. The window label
  stays inferred. No execution, Rust build, hosted CI, or gate.

Next question: bind callee1 `0x15206e0` and callee2 `0x151f870` (the chrono
timezone/day conversion pair), then the containing statistics body
`0x4898810..0x489a550`.
