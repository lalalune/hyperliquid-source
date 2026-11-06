# RE-001-node115-lu-bintableinit-caller-2sites-strinsert-18rsp: string insert caller, 2 sites

- Component ID: RE-001-node115-lu-bintableinit-caller-2sites-strinsert-18rsp
- Target release and full SHA-256: node #115,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  105,896,032 bytes
- Source commit / reference commit: upstream main
  05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation for the window census, site blocks, branches,
  tables, and tail; inference for the node-insert reading of the tail;
  unresolved for all helper internals (including the key helper's
  null-return semantics)
- Scope included and excluded: FDE `0x63d4497..0x63d463e` only.
  bin_table_init body (#262), lu-miss handler (#215), all helper bodies,
  all tables and globals, and neighboring FDEs are cited/read, not claimed.

## Reproduce

Worktree `hl-wt-calls295-115` at upstream main
`05bc2de303c05525b71e7e257426e741bc66a390`. Static analysis only;
the binary was never executed. Targeted objdump:

```
objdump -d --start-address=0x63d4497 --stop-address=0x63d463e \
  artifacts/node/115/hl-node
```

Verifier: `python3 tools/node115_lu_bintableinit_caller_strinsert_18rsp_2sites.py`
(exit 0). Unit tests:
`python3 tests/test_node115_lu_bintableinit_caller_strinsert_18rsp_2sites.py`
(exit 0).

## Evidence

- Window: FDE `0x63d4497..0x63d463e`, 423 bytes, 106 strict lines,
  11 calls, 1 ret. Previous FDE `0x63d4425..0x63d4497` (gap 0),
  next FDE `0x63d463e..0x63d46b4` (padding 0); adjacent, not overlapping.
- Frame: pushes r15/r14/r13/r12/rbp/rbx (no `endbr64`),
  `sub $0x1a8,%rsp`, canary at `0x198(%rsp)`, canary check at
  `0x63d4614..0x63d4625`.
- Entry: rdi = context (rbp), rsi = key (r13), rdx = string (r12).
  `strlen` at `0x63d44c7`; size helper `0x63d3eee` at `0x63d44d3`;
  size gate `cmp $0x1000,%r14` at `0x63d44db` (r14 = len+0x19);
  threshold table `0x67277c0` indexed by `(len+0x20)>>3` below the
  gate; size-class helper `0x63d3b3d` at `0x63d44fc` above it.
  Key helper `0x6364880` at `0x63d450f` (rdi = context,
  rsi = size-helper result, rdx = len+0x19, rcx = size class, r8 = 0);
  return in rbx is the node pointer. Null return jumps to the shared
  tail at `0x63d45a3`; the tail writes through rbx, so the null
  path's runtime semantics are not decoded here.
- Site 1 at `0x63d4534`: block `0x63d452c`
  (`lea 0x18(%rsp),%r15; mov %r15,%rdi`), fall-through only on
  `test %rbp,%rbp; jne 0x63d453c` (null context); rejoin
  `mov %r15,%rsi` into the phase-1 helper call.
- Phase-1 helper `0x63d3f0e` at `0x63d4542` (rdi = context,
  rsi = table, rdx = node); node resolution through `0x6727a00`
  indexed by phase-1 `eax` at `0x63d4558` (r14 = resolved value).
- Site 2 at `0x63d4570`: block `0x63d4568`
  (`lea 0x18(%rsp),%r15; mov %r15,%rdi`), fall-through only on
  `test %rbp,%rbp; jne 0x63d4578` (null context); rejoin
  `mov %r15,%rdx` into the phase-2 helper call setup.
- Phase-2 helper `0x63d4048` at `0x63d4581` (rdi = rsp,
  rsi = context, rdx = table, rcx = node); on return, index table
  `0x65096c0` indexed by `(value & 0xfff)` at `0x63d459a`,
  then `lock add %r14,0x38(%r9)` at `0x63d459e` (refcount
  increment; 0 `lock sub`).
- Shared tail from `0x63d45a3`: globals `0x6714728` (empty check),
  `0x6714720` (last node), `0x67147b8` (counter); node at rbx gets
  `+0 = 0`, `+8 = old counter`, `+0x10 = entry rsi (r13, via xmm)`,
  `+0x18 = strcpy` dest for the entry rdx string (r12);
  `strcpy` at `0x63d45f0`; register helper `0x63d39a0` at
  `0x63d460b` (rdi = context, rsi = `lea 0x6714740`, rdx = node);
  return value `0x8(%rbx)` in rax.
- Exit: single `ret` at `0x63d463d`; the window's two unconditional
  jumps (`0x63d44f7 -> 0x63d4503`, `0x63d45b4 -> 0x63d45c0`) both
  target inside the window. No scans, no move-to-front, no lu-miss
  sites: both phases are helper calls.
- `.hex` exhibits are raw binary bytes, not hex text.
- `.rela.dyn`: 60,723 total / 59,534 RELATIVE (readelf `-W`;
  non-wide output truncates the JUMP_SLOT type name and
  undercounts). `.rela.plt`: 278 entries, counted separately.
  Total FDEs from the verifier's own `.eh_frame` parse: 135,313
  (method: fixed 4-byte FDE range fields, PC-relative sdata4
  initial locations, CIE offsets in hex, FDE list sorted before
  bisect).
- Raw `0xe8` census: 108 total, tiers 10x1, 8x1, 6x2, 5x1, 4x8,
  2x12, 1x17; this FDE holds 2 raw sites, matching its 2 objdump
  sites. Raw counts are an upper bound; site counts come from
  objdump mnemonics.

## Implementation and comparison

Not yet implemented/measured. This packet is observation only.

## Results and limitations

- Static verifier exit 0 (see README for the check count from the
  final sealed run). Own unit tests exit 0 (tamper controls first:
  hex flip, strict-count change, call-site change, injected partial
  overlap of a prior window — each fails the temp-copy verifier;
  the clean temp copy passes).
- `make verify` exit 0. `make catalogue-check` reports the
  pre-existing `Stale catalogue: README.md` failure on the new base
  (also present on a pristine checkout); not a packet regression.
- Full `make test` is not run (584 files on the new base; hours of
  runtime and VM-restart risk). This deviation from the repository's
  stated gate is declared here rather than hidden.
- Disjointness: range-only collector over merged-tree +
  prior-worktree records (exhibits/windows only, all range-bearing
  forms, decimal-integer start/end accepted, plain `int(x, 16)` for
  hex strings, 0 skipped) — NONE for every exhibit range in this
  packet. The next window `0x63d61a0..0x63d6575` and the remaining
  fall-through candidate were also checked against all priors:
  NONE each.
- Unresolved: all helper internals; the key helper's null-return
  semantics; the phase-1 helper's `eax`/`edx` contract; the
  phase-2 helper's out-parameter at `rsp`.
