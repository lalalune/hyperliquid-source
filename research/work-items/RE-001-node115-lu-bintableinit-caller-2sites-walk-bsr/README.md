# RE-001-node115-lu-bintableinit-caller-2sites-walk-bsr

Tenth 2-raw bin_table_init caller packet (after #288, #289, #290, #291,
#292, #293, #294, #295, #296) and the LAST surviving 2-raw candidate.
The window is a bsr-size walk routine: a size computation with two bsr
overflow arms feeds a size class, helper `0x6365150` derives the key,
then a two-phase context-table walk with 8-slot move-to-front scans
resolves the node and increments its refcount, and the single `ret`
returns the resolved node value. Both bin_table_init sites pass the
same in-block stack temp `lea 0x10(%rsp)`, each block entered only by
a null-context `je`.

## Window

- FDE `0x63ed8b0..0x63edf05`, 1621 bytes, 338 strict mnemonic lines.
- Previous FDE `0x63ed870..0x63ed8a4` (gap 12 bytes, all `0xcc`).
- Next FDE `0x63edf10..0x63ee0a0` (padding 11).
- Frame: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx,
  `sub $0x1a8,%rsp`, canary at `0x198(%rsp)`.
- Entry: `rdi` = context (kept in `rbx`). Entry `rsi` is unused
  (overwritten before use).
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.

## Classification summary

- Size computation with two bsr blocks (`0x63edb11`, `0x63edd02`),
  threshold table `0x67277c0`, node-resolution table `0x6727a00`.
- Key helper `0x6365150` at `0x63ed9a9`; null return jumps to the
  shared epilogue returning 0.
- Phase-1 walk on the context+`0x1b0` table; phase-2 walk after the
  site-2 rejoin; `lock add %r14,0x38(%r11)` at `0x63eda62`.
- Bin_table_init sites: `0x63edb88` (block `0x63edb80`, via `r15`),
  `0x63edc65` (block `0x63edc58`, via `rdx`).
- Lu-miss sites: `0x63ede59` (scan-B exhaustion),
  `0x63edef6` (scan-A exhaustion).
- Scans: 8 slots each, table+`0x100`, move-to-front on a hit.
- Exit: single `ret` at `0x63edadd`, 0 tail jumps; all 55 jump
  instructions target inside the window.

Full site/scan tables, census, and method notes are in records.json
and EVIDENCE.md.

## Disjointness

Range-only collector over the merged tree plus all prior
`hl-wt-calls*` worktree records (exhibits/windows only, all
range-bearing forms, decimal-integer start/end accepted, plain
`int(x, 16)` for hex strings, 0 skipped). The window
`0x63ed8b0..0x63edf05` overlaps no prior range (verifier: see the
final verifier run figure below), including packet #296's window
`0x63d61a0..0x63d6575`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`. The window is clear of both 2-raw
exclusions: it starts at `0x63ed8b0`, after the `0x63ed090..0x63ed862`
exclusion ends, and it ends at `0x63edf05`, before the
`0x63ef8e0..0x63efba2` exclusion starts.

## Prior pointer verified (no correction)

#288/#296's survey pointer for this window (1621 bytes, 2
bin_table_init sites, 2 lu-miss sites, 1 ret, 2 bsr) is verified
correct by program arithmetic and by the objdump census above.

## 2-raw tier status

This packet exhausts the 2-raw tier: all 12 surveyed candidates are
now built (#288–#297) or excluded as whole FDEs (#260's first 215
bytes, #258's two ranges). The next frontier is the 1-raw tier
(17 FDEs); its survey belongs to packet #298, verified there, not
assumed here.

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_walk_bsr_2sites.py`:
  exit 0 (final check count from the sealing run: see below).
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_walk_bsr_2sites.py`
  (tamper controls first — hex flip, strict-count change, call-site
  change, injected overlap — each makes the temp-copy verifier fail;
  the clean temp copy passes): exit 0 (final check count from the
  sealing run: see below).
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

- Verifier: exit 0, 64 checks, 0 failures.
- Unit tests: exit 0, 11 checks, 0 failures.
- Disjointness: verifier scanned 54,648 priors, 0 skipped,
  NONE.
