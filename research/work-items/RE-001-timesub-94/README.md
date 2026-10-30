# RE-001: bind the node #94 shared "Time Sub" helper at 0x1447130

- Component: `foundation`; bounded static function validation under RE-001.
  This is not completion of RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Claim status: byte/record observations with explicit inferred labels and
  explicitly unresolved operand semantics; no reconstruction, no gate request.
- Scope included: the helper body `0x1447130..0x14472a0` (368 bytes), its FDE
  record, the comparison cascade, the microsecond conversion arithmetic, the
  `"Time Sub"` format anchor, five GOT-mediated targets, and the complete
  direct/indirect call census. Scope excluded: the inner callee `0x151d1b0`
  (its own date-style arithmetic with a 400-entry table), the format and
  panic callees, all 60 caller functions' own logic, #115, and visor.

## Question

What is the helper behind the widely-shared GOT slot `0x576e8c0` that the
ema_tracker update (separate packet) and the heartbeat-status body (PR #22)
both call, and how many consumers share it?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`;
`tools/elf_index.py --release 94` must have produced
`work/index/node-94-unwind.tsv` (the census uses it only to group call sites
into functions). The captured executable is only read as data.

```sh
python3 tools/elf_index.py --release 94
python3 tools/timesub_static.py --output work/timesub-record.json
diff work/timesub-record.json research/work-items/RE-001-timesub-94/observed/records.json
python3 -m unittest discover -s tests -p test_timesub_static.py -v
```

The tool authenticates size and SHA-256, then checks the exact FDE record and
body bytes, all nine verified conditional-branch destinations, the five
GOT-mediated call sites against their RELATIVE relocations, the `1e6` divisor
constant, the `"Time Sub"` string anchor and its in-body `lea`, the panic-state
global's initial value, and a whole-`.text` census of `e8`, slot-targeted
`ff 15`, and `lea` encodings. Disassembly text in `observed/` was rendered
with capstone 5.0.7 and labeled as such; byte records are authoritative.
Platform: Windows 10 22H2, Python 3.11.9; no binutils was available.

## Observations

Body `0x1447130..0x14472a0` (368 bytes, FDE at `.eh_frame` VA `0xfcf3a8`,
sha256 `53e1c201...`), reached only through GOT slot `0x576e8c0`.

Signature (observed, meaning unresolved): `rdi` points at a 12-byte operand A
(three dwords), `rsi` at a 12-byte operand B followed by a dword flag and a
16-byte descriptor; the f64 result returns in `xmm0`. The head cascade
compares A/0 against B/2 (`setl`), A/1 against B/1 (`setb`), then A/2 against
B/2 (`jb`) — a three-stage dword ordering whose field meaning stays open;
taken branches route to a format/saturate path that returns `0.0` (an odd
flag dword can route onward to a panic path gated by the global at
`0x577ab98`, initial value 3).

Compute path, from decoded instructions: the inner callee `0x151d1b0` returns
an `(i64 rax, i32 edx)` pair. If `rax < 0 and edx > 0`, `rax += 1` and
`edx -= 1e9`. Then `micros = rax_adjusted * 0xf4240` (immediate 1e6;
`imul` overflow returns `0.0` via `jo`), the adjusted `edx` is divided by
1000 through the `0x10624dd3`/shift-38 magic (validated as exact trunc
division for all signed 32-bit inputs in the grid test), and the sum's
overflow again returns `0.0`. The result is `f64(micros) / 1e6` with the
`1e6` constant at `0x20ae60`. The interpretation of the inner pair as a
seconds/nanoseconds split is inferred from the 1e6/1e9 constants only and
remains open until the inner callee family is bound.

The `"Time Sub "` format anchor sits at `0x1f9cb6`, referenced by
`lea rsi, [rip-0x124d547]` at `0x14471f6`; the format callee is `0x1344760`,
the dealloc callee `0x54c8cb0`, and the panic-path callee `0x4ee3b20`.

Call census over the entire `.text` (70,370,352 bytes): zero direct `e8`
references, zero `lea` references, 72 `ff 15` call sites through the single
GOT slot across 60 distinct FDE-indexed functions, including
`0x1479229` (ema_tracker update) and `0x4726c81` (the heartbeat-status body
mapped by PR #22, whose README left this callee unresolved).

## Implementation and comparison

Not yet implemented: no reconstructed Rust, no two-build comparison. The
microsecond conversion identity (magic division and borrow/overflow model)
was validated in Python over bounded grids including the full signed 32-bit
extremes for the division — arithmetic validation of decoded operands, not
target equivalence.

## Results and limitations

- 1 helper body bound to digest (368 bytes), 1 FDE record, 9 verified branch
  destinations, 5 GOT targets, 1 float constant, 1 string anchor, 1 global
  initial value; the census denominators are the complete `.text` for the
  three encodings scanned.
- 9 tests pass (identity, FDE bounds, magic-division grid, borrow/overflow
  model, body/FDE/constant/string/global/GOT-relocation mutation controls).
  Author rerun, not independent peer review.
- Unknowns: the operand field meanings, the inner callee `0x151d1b0`
  (observed: 400-cycle division and a 400-entry lookup table on the leading
  dwords), the format/panic callee semantics, and what distinguishes the 72
  call sites' descriptors. No execution, Rust build, hosted CI, or gate.

Next question: bind `0x151d1b0` — the 12-byte-operand difference core with
its 400-entry leap-style table — and one full consumer (the ema_tracker
caller's window guard at `0x474fb90`).
