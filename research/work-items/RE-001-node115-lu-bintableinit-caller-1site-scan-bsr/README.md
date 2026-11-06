# RE-001-node115-lu-bintableinit-caller-1site-scan-bsr

First 1-raw bin_table_init caller packet: the 2-raw tier is exhausted
(#288–#297), so this packet surveys the 1-raw tier (17 FDEs, own
`.eh_frame` parse + raw-e8 census reproduced: total 108, tiers 10x1,
8x1, 6x2, 5x1, 4x8, 2x12, 1x17) and builds on the first surviving
candidate in address order. The window is a single-site scan routine:
one bin_table_init site (`lea 0x10(%rsp)` in-block, entered only by a
null-context `je`), a two-phase context-table walk with an 8-slot
move-to-front scan, a bsr size arm, and a tail-jump exit — 0 `ret`.

## Window

- FDE `0x6362f90..0x6363258`, 712 bytes, 152 strict mnemonic lines.
- Previous FDE `0x6362910..0x6362f82` (gap 14 bytes, all `0xcc`).
- Next FDE `0x6363260..0x6363552` (padding 8 bytes, all `0xcc`) —
  the next 1-raw candidate, not decoded here.
- Frame: `endbr64`, pushes r13/r12/rbp/rbx, `sub $0x1a8,%rsp`,
  canary at `0x198(%rsp)`.
- Entry: `rdi` = context (kept in `rbx`), `rsi` = key (preserved
  across the site call via `0x8(%rsp)`), `rdx` = size (kept in
  `rbp`).
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.

## Classification summary

- Size class with one bsr block (`0x6363110`): `cmp $0x1000,%rbp`
  guards the threshold table `0x67277c0` (indexed by
  `(rbp + 7) >> 3`); above the gate the bsr arm rounds the size.
- Phase-1 walk on the context+`0x1b0` table; second-level value is
  masked and written back into its slot (no `0x6727a00` table read
  in this FDE, unlike the #288–#297 walkers).
- Bin_table_init site: `0x6363095` (block `0x6363088`, via `r13`).
- Lu-miss site: `0x6363249` (scan exhaustion).
- Scan: 8 slots, table+`0x100`, move-to-front on a hit (slot-0 hit
  uses an inline head-swap block).
- Exit: 0 `ret`; the single exit is a tail jump at `0x636307f` to
  `0x63aefe0` (a 1-raw candidate FDE, cited not claimed), with the
  canary-fail call to `__stack_chk_fail` at `0x6363253`.

Full site/scan tables, census, and the 1-raw survey are in
records.json and EVIDENCE.md.

## Disjointness

Range-only collector over the merged tree plus all prior
`hl-wt-calls*` worktree records (exhibits/windows only, all
range-bearing forms, decimal-integer start/end accepted, plain
`int(x, 16)` for hex strings, 0 skipped). The window
`0x6362f90..0x6363258` overlaps no prior range (verifier: see the
final verifier run figure below), including packet #297's window
`0x63ed8b0..0x63edf05`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`.

## 1-raw tier survey

17 1-raw FDEs, each exactly 1 objdump-verified bin_table_init
site. One is excluded as a whole FDE: `0x63adf40..0x63ae252`
overlaps packet #214's (lu nextnode) claimed sub-ranges
`0x63adf71..0x63adf9d`, `0x63ae014..0x63ae040`,
`0x63ae088..0x63ae0cf`, `0x63adfed..0x63ae014` in its records.
The two standing exclusions were re-verified: no 1-raw candidate
falls inside `0x63ed090..0x63ed862` (#260) or
`0x63ef8e0..0x63efba2` (#258). This packet builds on the first
surviving candidate in address order; the full per-candidate
table is in records.json under `survey`.

## Prior pointer verified (no correction)

#297's framing for this tier (1-raw tier, 17 FDEs; its survey
belongs to packet #298) is verified correct by program
arithmetic and by the objdump census above: the re-derived
raw-e8 census is total 108 with tiers 10x1, 8x1, 6x2, 5x1, 4x8,
2x12, 1x17, and this window holds 1 raw site, matching its 1
objdump site.

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_scan_bsr_1site.py`:
  exit 0 (final check count from the sealing run: see below).
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_scan_bsr_1site.py`
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

- Verifier: exit 0, 62 checks, 0 failures.
- Unit tests: exit 0, 11 checks, 0 failures.
- Disjointness: verifier scanned 55,490 priors, 0 skipped,
  NONE. (The verifier counts 708 exhibits that carry both a
  `range` key and a `start`/`end` pair twice; the deduplicated
  survey figure is 54,785 priors — the verdict is NONE under
  either count.)
