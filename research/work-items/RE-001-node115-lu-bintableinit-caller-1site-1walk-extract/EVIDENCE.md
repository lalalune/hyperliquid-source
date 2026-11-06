# RE-001-node115-lu-bintableinit-caller-1site-1walk-extract: single-walk lookup-with-extract caller

- Component ID: RE-001-node115-lu-bintableinit-caller-1site-1walk-extract
- Target release and full SHA-256: node #115 only,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  105,896,032 bytes
- Source commit / reference commit: upstream main
  05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly census + static verifier);
  the `.bss` contents at 0x6511a00 / 0x6711b40 are unresolved (not in
  the file) and are claimed only as referenced addresses
- Scope included and excluded: FDE 0x63bc490..0x63bc728 only (664
  bytes, 145 strict lines). Excluded: bin_table_init body
  0x63d9880..0x63d9a64 (#262), lu-miss handler 0x63d9700..0x63d987b
  (#215), prev/next FDEs, tail-jump targets, and the runtime
  contents of the two `.bss` objects.

## Reproduce

Working directory: a worktree of lalalune/hyperliquid-source at
upstream main 05bc2de303c05525b71e7e257426e741bc66a390
(`~/workspace/hl-wt-calls311-115`, branch
`codex/re-004-calls311-115`).

- `python3 tools/node115_lu_bintableinit_caller_1walk_extract_1site.py`
  (exit 0, 172 checks, 0 failures).
- `python3 tests/test_node115_lu_bintableinit_caller_1walk_extract_1site.py`
  (exit 0, 12 checks, 0 failures).
- `make verify` (exit 0, 559 manifests, 7159 entries).
- `make catalogue-check` (exit 2, pre-existing `Stale catalogue:
  README.md`, also on a pristine checkout).
- Objump exhibit regeneration: `objdump -d
  --start-address=0x63bc490 --stop-address=0x63bc728
  artifacts/node/115/hl-node` (matches the exhibit; the unit
  tests re-run this).
- No execution of the node binary anywhere in this packet; byte
  reads only. Full `make test` not run (584 files; declared
  deviation, see README).

## Evidence

- FDE bounds from an own `.eh_frame` parse (135,313 FDEs, sorted
  before bisect): target 0x63bc490..0x63bc728 (664 bytes); prev
  0x63bc480..0x63bc489 (gap 7, all `0xcc`); next
  0x63bc730..0x63bcb12 (padding 8, all `0xcc`).
- Strict mnemonic lines: 145. Calls: 3 — bin_table_init
  0x63bc5e5 -> 0x63d9880, lu-miss 0x63bc719 -> 0x63d9700,
  `__stack_chk_fail` 0x63bc723 -> 0x63f0d70. Ret: 1
  (0x63bc59e). Bsr: 0. Lock: 0/0. Jumps: 20, all inside the
  window (no tail-jump exit).
- Bin_table_init site 0x63bc5e5: block 0x63bc5d8,
  `lea 0x10(%rsp),%r15`, `rsi` saved to `0x8(%rsp)` and
  restored, rejoin `jmp 0x63bc4d4`; entered only by the
  null-context `je` at 0x63bc4ce.
- Walk: top index `(key >> 0x1a) & 0xf0`, high bits
  `key & 0xffffffffc0000000`, compare `cmp %rdi,%rcx` at
  0x63bc4f0, mismatch to the scan; second level
  `(key >> 0x9) & 0x1ffff8 + table + 0x8`, loaded into `rcx`
  at 0x63bc50e.
- Extract: `shl $0x10` / `sar $0x10` + `and
  $0xffffffffffffff80`; zero path on
  `(value << 16) <= 0x7fffff`; page of node+0x10 to `*r12`;
  flag path on bit 12 of the descriptor clear (`*rbp` = 0,
  `*rbx` = 1); otherwise index `(desc >> 0x1c) & 0x3ff` to
  `*rbp` and byte-indexed 40-byte-entry table field (+0x10)
  at 0x6711b40 to `*rbx`.
- Scan: 8 slots, table+0x100 in `r15`, key in `rcx`; one
  reversed-operand compare (slot 6, 0x63bc6d9); slot 7
  memory-direct (0x63bc6e6); slot-0 hit block
  0x63bc601..0x63bc62f, shared move-to-front block 0x63bc647.
- Lu-miss 0x63bc719: `rdi` = `r14` context, `rsi` =
  0x6511a00 (`.bss`, NOT entry `rsi`), `rdx` = `r15`,
  `rcx` = entry `rsi`, `r8d` = 1, `r9d` = 0; rejoin
  `jmp 0x63bc50e`.
- Section check (own ELF parse): `.bss` is
  0x64ffe40..0x6728d24, NOBITS; both 0x6511a00 and 0x6711b40
  lie inside it, so neither has file bytes.
- Exit: `eax` = 0 at `ret` (entry xor + top-index `and
  $0xf0,%eax` + epilogue canary load-and-subtract); no
  `sete`, no null-flag epilogue.
- Raw-`0xe8` census: 108 total, tiers 10x1, 8x1, 6x2, 5x1,
  4x8, 2x12, 1x17; this FDE raw 1.
- `.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`:
  278 entries, counted separately.
- Disjointness: verifier scanned 66,436 priors, 0
  skipped, NONE (deduplicated figure 65,598 after removing
  838 within-file duplicate ranges).
- 1-raw tier: 17 candidates surveyed, 16 survive, 1 excluded
  as a whole FDE (0x63adf40..0x63ae252 overlaps packet #214).
  #310's pointer for this window verified correct by program
  arithmetic and objdump census — no correction.
- Fall-through re-verified by program: 0x63bc730..0x63bcb12
  (994B, 212 strict, 6 calls, 1 bti 0x63bc9ec, 1 miss, 1 ret
  0x63bc83e, 0 bsr, 27 jumps, tail jump 0x63bc93b -> 0x63f0b70),
  0x63c2f00..0x63c3328 (1064B, 230 strict, 10 calls, 1 bti
  0x63c30ed, 1 miss, 1 ret 0x63c30cf, bsr 1 at 0x63c31a1,
  31 jumps, tail jump 0x63c3132 -> 0x63d72b0).

## Implementation and comparison

Not yet implemented/measured (static packet only): no Rust
reconstruction of this routine exists yet. The verifier is a
static Python checker (byte reads only); the unit tests are
tamper controls plus independent recounts and objdump
regeneration, not a reimplementation.

## Results and limitations

- Verifier: exit 0, 172 checks, 0 failures.
- Unit tests: exit 0, 12 checks, 0 failures.
- `make verify`: exit 0 (559 manifests, 7159 entries).
- `make catalogue-check`: exit 2, pre-existing failure, not a
  packet regression.
- Disjointness: verifier scanned 66,436 priors, 0 skipped,
  NONE (deduplicated figure 65,598 after removing 838
  within-file duplicate ranges).
- Unknown: the runtime contents of the `.bss` objects at
  0x6511a00 and 0x6711b40; the caller-side meaning of the entry
  key and of `r8d`/`r9d`; the semantics of the three output
  values beyond the store sites; the table entries' other
  fields besides +0x10.
- Next question: packet #312 decodes 0x63bc730..0x63bcb12
  (994 bytes, 1 bin_table_init site, 1 lu-miss site, 1 ret,
  0 bsr, tail-jump exit to 0x63f0b70).
