# RE-001: bind the node #94 std Once state machine 0x4ee3b20

- Component: `foundation`; bounded static function validation under RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Claim status: byte/record observations; the std Once label is inferred from
  the poison message, the state machine and the futex sequences; no
  reconstruction, no gate request.
- Scope included: the 540-byte body `0x4ee3b20..0x4ee3d3c` (FDE `0x12f68c0`),
  twelve immediate anchors, the four-entry jump table at `0x7cb390` with all
  computed dispatch targets, the futex wake/wait sequences, the poison panic
  site with its message bytes and callee, and the whole-`.text` census.
- Scope excluded: the read-lock guards and their cell (bound in
  `RE-001-lock-descriptor-94`), the futex wrapper behind slot `0x576ea40`, the
  TLS slot getter behind `0x576e8d8`, the 1252 caller families, #115, visor.

## Question

Both read-lock guards consult the once machinery through GOT slot
`0x576e8b8` (#636): what does that callee do, and how widely is it shared?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`.

```sh
python3 tools/once_state_static.py --output work/once-record.json
diff work/once-record.json research/work-items/RE-001-once-state-94/observed/records.json
python3 -m unittest discover -s tests -p test_once_state_static.py -v
```

The tool authenticates size and SHA-256, then checks the exact body and FDE,
twelve anchors (the state load, both state masks, both `lock cmpxchg`
dword sites, four futex selector sites, the wait/wake operations, both
wake-all counts, the poison operand), the jump table lea and all four
displacement targets with both indexed-dispatch sites, the poison panic lea,
message bytes, callee and unwind resume, and the census. Disassembly text in
`observed/` was rendered with capstone 5.0.7 and labeled as such; byte
records are authoritative. Platform: Windows 10 22H2, Python 3.11.9.

## Observations

The body runs a two-bit state machine over a dword at `[rdi]` (mask 3 plus a
waiter flag at bit 2), entered with a force flag in `esi` and a closure
context dispatched through `[rax + 0x20]`. The non-force path dispatches
through a four-entry jump table at `0x7cb390` whose computed targets are
`0x4ee3c3a`, `0x4ee3c76`, `0x4ee3cf7` and `0x4ee3c52`; the index-2 target is
the poison block. Two `lock cmpxchg` dword sites claim the state and one
`xchg` publishes the completion value. Blocked paths call an indirectly
loaded futex wrapper with the selector `0xca` (SYS_futex on x86-64) — the
wait operation `0x89` with the expected state and the wake operation `0x81`
with the count `0x7fffffff` (wake all) — through slots `0x576ea40`/`0x576e8d8`
that carry no static relocations. The poison block loads the message at
`0x7cd78c` (beginning `Once instance has previously been poisoned`), passes
the operand `0x55`, and calls `0x157b810` through GOT slot `0x576e098` before
resuming the unwind at `0x5660110`.

Census over the complete `.text`: GOT slot `0x576e8b8` receives 1252 `ff 15`
call sites with zero direct `e8` and zero `lea` references — by site count
the most-shared helper measured in this series (read-lock helper 952,
day-count constructor 324, NaiveTime/NaiveDate 133/150, Time Sub 72). The
lock-cell sibling guard's call site `0x358dc26` is among them.

## Implementation and comparison

Not implemented: no reconstructed Rust, no two-build comparison.

## Results and limitations

- 1 body (540 bytes) + FDE, 12 anchors, 1 jump table with four validated
  targets and both dispatch sites, 4 futex call sites, 1 poison panic with
  message and callee; census denominator is the complete `.text` for
  `e8` / `ff 15` / `lea` encodings.
- 7 tests pass (record match, dispatch table, futex sequence, poison panic,
  census, body and jump-table mutation controls). Author rerun, not
  independent peer review.
- Unknowns: the futex wrapper internals, the TLS slot getter, and what the
  1252 caller families guard. The std Once label stays inferred (the state
  values and exact std semantics are not reconstructed). No execution, Rust
  build, hosted CI, or gate.

Next question: the futex wrapper behind `0x576ea40` and a census-driven
sample of the 1252 call sites.
