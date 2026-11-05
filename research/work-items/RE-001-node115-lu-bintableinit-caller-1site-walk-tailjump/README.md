# RE-001-node115-lu-bintableinit-caller-1site-walk-tailjump

Second 1-raw bin_table_init caller packet (after #298). The window is a
single-site walk routine: one bin_table_init site (`lea 0x10(%rsp)`
in-block, entered only by a null-context `je`), a two-phase
context-table walk with an 8-slot move-to-front scan, a field-update
tail, and two exits — one `ret` and one tail jump to `0x63bd6c0`.

## Window

- FDE `0x6363260..0x6363552`, 754 bytes, 161 strict mnemonic lines.
- Previous FDE `0x6362f90..0x6363258` (gap 8 bytes, all `0xcc`) —
  packet #298's window, adjacent, not overlapping.
- Next FDE `0x6363560..0x636365a` (padding 14 bytes, all `0xcc`).
- Frame: `endbr64`, pushes r13/r12/rbp/rbx, `sub $0x1a8,%rsp`,
  canary at `0x198(%rsp)`.
- Entry: `rdi` = context (kept in `rbp`), `rsi` = key (kept in
  `r12`), `rdx` = struct pointer (kept in `r13`).
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.

## Classification summary

- Phase-1 walk on the context+`0x1b0` table; on a top-level match the
  second-level value is shifted/masked and written back into its slot
  — no `0x6727a00` table read in this FDE, unlike the #288–#297
  walkers.
- Bin_table_init site: `0x63633f8` (block `0x63633f0`, via `rbx`).
- Lu-miss site: `0x636353e` (scan exhaustion).
- Scan: 8 slots, table+`0x100`, move-to-front on a hit.
- Calls: `0x63aefe0` (1-raw candidate #12, cited), `0x63eb870`
  (helper), plus bin_table_init, lu-miss, `__stack_chk_fail`.
- Field-update tail: `0x368(%r13)` / `0x37a(%r13)` compare, key stored
  at `-0x8(%r10)`.
- Exit: single `ret` at `0x636336e`, plus one tail jump at `0x636339a`
  to `0x63bd6c0` (exit-ness verified per FDE: `0x63bd6c0` was a
  tail-jump exit in #288 but an ordinary call in #287/#289).

Full site/scan tables, census, and method notes are in records.json
and EVIDENCE.md.

## Disjointness

Range-only collector over the merged tree plus all prior
`hl-wt-calls*` worktree records (exhibits/windows only, all
range-bearing forms, decimal-integer start/end accepted, plain
`int(x, 16)` for hex strings, 0 skipped). The window
`0x6363260..0x6363552` overlaps no prior range (verifier: see the
final verifier run figure below), including packet #298's window
`0x6362f90..0x6363258`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`.

## Prior pointer verified (no correction)

#298's survey pointer for this window (754 bytes, 1 bin_table_init
site, 1 lu-miss site, 1 ret, 0 bsr) is verified correct by program
arithmetic and by the objdump census above.

## 1-raw tier status

Packet #298 surveyed all 17 1-raw candidates (each exactly 1
objdump-verified bin_table_init site). 16 survive; 1 is excluded as
a whole FDE (`0x63adf40..0x63ae252`, overlapping #214's claimed
sub-ranges). This packet builds on the second survivor. The next
frontier is packet #300 on `0x63637f0..0x6363d50`.

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_walk_tailjump_1site.py`:
  exit 0 (final check count from the sealing run: see below).
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_walk_tailjump_1site.py`
  (tamper controls first — hex flip, strict-count change, call-site
  change, injected overlap — each makes the temp-copy verifier fail;
  the clean temp copy passes): exit 0 (final check count from the
  sealing run: see below). The test harness uses lean temp copies
  (verifier + packet dir + symlinked binary only); a full worktree
  copy changes nothing the verifier reads.
- `make verify`: exit 0 (559 evidence-packet manifests, 7159
  entries).
- `make catalogue-check`: exit 2 with the pre-existing `Stale
  catalogue: README.md` failure, also present on a pristine
  checkout; not a packet regression.
- Full `make test` is not run (584 files on the new base; hours of
  runtime and VM-restart risk). This deviation from the repository's
  stated gate is declared here rather than hidden.
- `.hex` exhibits are raw binary bytes, not hex text.

## Sealing-run figures

- Verifier: exit 0, 60 checks, 0 failures.
- Unit tests: exit 0, 12 checks, 0 failures.
- Disjointness: verifier scanned 56,332 priors, 0 skipped,
  NONE.
