# RE-001-node115-lu-tail-route: the node #115 lu tail route end to end

- Component ID: RE-001-node115-lu-tail-route
- Target release and full SHA-256: node #115,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: upstream main 8fd8db6 (unmoved by
  fetch before analysis)
- Claim status: observation for all byte-grounded claims; inference
  is marked as such (the entry-embeds-C +0x38 shift is an alignment
  observation; the C+0x78/C+0x80 label correspondence is
  consistent-with, not proof); unresolved items are listed in README
- Scope included and excluded: included — tail route FDE
  `0x635f4b0..0x635f697` end to end, its three call shapes, its
  census, and its first-level helpers characterised only. Excluded —
  full decodes of helpers `0x6369790` / `0x63697a0` / `0x63a96f0` /
  `0x63bfb90` / `0x63bfb60` / `0x63bfc00` / `0x63bfc40`, the
  workers `0x63c19a0` / `0x63c1930`, and all other open items.

## Reproduce

Worktree `~/workspace/hl-wt-calls207-115`, branch
`codex/re-004-calls207-115`, base upstream main `8fd8db6`.
Static analysis only: bytes were read, the node binary was never
executed. Coordinate system: `.text` file offset = VA − 0x1000
(section addr 0x1419300, file offset 0x1418300, size 0x4fd7700).

- `objdump -d --start-address=0x635f4b0 --stop-address=0x635f697
  artifacts/node/115/hl-node` — full tail-route disassembly.
- `objdump -d --start-address=0x635fbe5 --stop-address=0x635fc30 ...`
  — inner→tail call-site setup.
- `objdump -d --start-address=0x63610e0 --stop-address=0x6361160 ...`
  — FDE `0x6360ed0` tail-call setup.
- `readelf --debug-dump=frames-interp artifacts/node/115/hl-node`
  (streamed through grep, never saved) — FDE bounds: tail
  `0x635f4b0..0x635f697`, predicate `0x6369790..0x636979f`,
  drain `0x63697a0..0x63697d2`, accumulator
  `0x63a96f0..0x63a974a`, C-sequence stubs 8–11B each.
- Whole-`.text` byte scan + `.rela.dyn` RELATIVE scan (in the
  verifier) — census for `0x635f4b0`.
- `python3 tools/node115_lu_tail_route.py` — static verifier,
  exit 0.
- `python3 tests/test_node115_lu_tail_route.py` — unit tests, 8/8.
- `make doctor`, `make verify`, `make catalogue-check`,
  `make test` — full gates (see README Verification).

No execution, no network, no side effects. Scratch was kept small
(excerpts + pr_body.md only); no whole-section dumps were saved.

## Evidence

- Tail FDE `0x635f4b0..0x635f697` (423B). Starts with push
  prologue `41 57 41 56` (no `endbr64`); r13 = arg4 (rcx),
  r12 = C (rdx), rbp = thread (rdi), rsi = seg.
- Table lookup (`tail_lookup.hex`, 43B / 10 strict): mov
  [seg+0x13450] at `0x635f4e0`; lea table base `0x6711aa0` at
  `0x635f4e6`; `divq` at `0x635f4ed` with divisor lea
  `0x6711aa8` at `0x635f4c9`; stride built as 13*16 (lea*3,
  lea*13, shl 4) at `0x635f4f0`/`0x635f4f4`/`0x635f4f8`;
  entry+0x78 lea at `0x635f4ff`; trylock call at `0x635f506`
  → `0x63f17b0`.
- Entry owner dance: entry+0x70 += 1 at `0x635f50f`;
  [entry+0x68] vs thread at `0x635f514`; entry+0x60 += 1 at
  `0x635f51a`; [entry+0x68] = thread at `0x635f51f`.
  Entry-trylock failure: entry+0xa0 = 1 at `0x635f540`.
- Predicate (`tail_pred.hex`, 27B / 7 strict): call
  `0x6369790` at `0x635f526`; test at `0x635f52b`; false →
  entry+0xa0 = 0 at `0x635f52f`, unlock at `0x635f539`.
- Table byte: movzbl entry+0xac at `0x635f570`; nonzero →
  xor esi,esi at `0x635f640`, drain call `0x63697a0` at
  `0x635f645`.
- C lock: lea C+0x40 at `0x635f580`; trylock call at
  `0x635f588` → `0x63f17b0`; failure → C+0x68 = 1 at
  `0x635f650`. C owner dance: C+0x38 += 1 at `0x635f595`;
  [C+0x30] vs thread at `0x635f59b`; C+0x28 += 1 at
  `0x635f5a2`; [C+0x30] = thread at `0x635f5a8`.
- C+0x78 gate: mov [C+0x78] at `0x635f5ad`; jle at
  `0x635f5b5`. C-sequence calls: `0x63bfb90` at `0x635f5c7`
  (rdi = entry+0xb0, `0x635f5bb`), `0x63bfb60` at
  `0x635f5d2`, `0x63bfc00` at `0x635f5e7` (rsi = C+0x88,
  `0x635f5d7`), gating test at `0x635f5f1`, `0x63bfc40`
  at `0x635f5f8`.
- Arg4 branch (`tail_accum.hex`, 21B / 5 strict): test r13
  at `0x635f5fd`; mov r13,rdx at `0x635f678`; accumulator
  call `0x63a96f0` at `0x635f681`; add rax,entry+0xb8 at
  `0x635f686`.
- Threshold (`tail_drain.hex`, 39B / 6 strict + 2
  byte-continuation lines): cmpq $0x400,entry+0xb8 at
  `0x635f610`; jbe at `0x635f61b`; entry+0xb8 = 0 at
  `0x635f621`; drain call `0x63697a0` at `0x635f632`.
- Inner call site (`tail_callsite.hex`, 57B / 15 strict):
  mov [C+0x6e8] at `0x635fbe5`; C flag clear at
  `0x635fbec`; C unlock call at `0x635fbf5`; runtime-byte
  test at `0x635fc03`; 6th-arg test at `0x635fc08`;
  arg4 = [C+0x6e8] at `0x635fc0d`; tail call at
  `0x635fc19` → `0x635f4b0`; return discarded
  (`xor eax,eax` at `0x635fc22`).
- Third caller: own rcx spilled at `0x6360f93`, own r8
  overwrite at `0x6361050`, reload at `0x6361119`, tail
  call at `0x6361129` → `0x635f4b0`; skipped when r12b
  nonzero (`0x6361110`); post-call target `0x6360fb8`
  overwrites eax via its first helper call, so the tail
  return is discarded here too.
- Gate: E9 at `0x6360695` → `0x635f4b0` (arg4 = 0,
  `0x636068e`, per #206's `gate_tail.hex`).
- Census (own byte scan + per-site disassembly check):
  tail `0x635f4b0`: 2 E8 (`0x635fc19`, `0x6361129`),
  1 E9 (`0x6360695`), 0 LEA, 0 GOT. The `.rela.dyn`
  scan was validated against #204's known entry (GOT slot
  `0x64ee138`, RELATIVE addend `0x6711b40`, found).
- Disjointness: all 5 excerpts are disjoint from #202–#206
  exhibit ranges; `tail_callsite` starts exactly at
  #206's `inner_call` end (`0x635fbe5`) — adjacent, not
  overlapping.

## Implementation and comparison

Not yet implemented/measured — evidence packet only, no
reconstruction code changed.

## Results and limitations

- Verifier exit 0 (5 excerpts, key-byte sites, census,
  disjointness, MANIFEST 15/15); unit tests 8/8; full gates
  per README Verification.
- What remains unknown is listed under Unresolved in README.
  If requesting no gate, say so: no gate is requested by this
  packet beyond the standard evidence-packet checks.
- Next question: decode drain helper `0x63697a0` end to end
  (see README).
