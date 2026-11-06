# RE-001-node115-lu-bintableinit-caller-1site-1walk-extract-trylock: single-walk lookup-with-extract trylock caller

- Component ID: RE-001-node115-lu-bintableinit-caller-1site-1walk-extract-trylock
- Target release and full SHA-256: node #115 only,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  105,896,032 bytes
- Source commit / reference commit: upstream main
  05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly census + static verifier);
  the `.bss` contents at 0x6511a00 / 0x6711b40 are unresolved (not in
  the file) and are claimed only as referenced addresses; the
  lock-wait helper, fallback helper, and mutex node fields are
  claimed only as the code uses them
- Scope included and excluded: FDE 0x63bc730..0x63bcb12 only (994
  bytes, 212 strict lines). Excluded: bin_table_init body
  0x63d9880..0x63d9a64 (#262), lu-miss handler 0x63d9700..0x63d987b
  (#215), lock-wait helper 0x63bf680..0x63bf7ee (#251), fallback
  helper FDE 0x63abd00..0x63ac0cc, prev/next FDEs, PLT stubs, and
  the runtime contents of the two `.bss` objects.

## Reproduce

Working directory: a worktree of lalalune/hyperliquid-source at
upstream main 05bc2de303c05525b71e7e257426e741bc66a390
(`~/workspace/hl-wt-calls312-115`, branch
`codex/re-004-calls312-115`).

- `python3 tools/node115_lu_bintableinit_caller_1walk_extract_trylock_1site.py`
  (exit 0, 163 checks, 0 failures).
- `python3 tests/test_node115_lu_bintableinit_caller_1walk_extract_trylock_1site.py`
  (exit 0, 12 checks, 0 failures).
- `make verify` (exit 0, 559 manifests, 7159 entries).
- `make catalogue-check` (exit 2, pre-existing `Stale catalogue:
  README.md`, also on a pristine checkout).
- Objump exhibit regeneration: `objdump -d
  --start-address=0x63bc730 --stop-address=0x63bcb12
  artifacts/node/115/hl-node` (matches the exhibit; the unit
  tests re-run this).
- No execution of the node binary anywhere in this packet; byte
  reads only. Full `make test` not run (584 files; declared
  deviation, see README).

## Evidence

- FDE bounds from an own `.eh_frame` parse (135,313 FDEs, sorted
  before bisect): target 0x63bc730..0x63bcb12 (994 bytes); prev
  0x63bc490..0x63bc728 (#311, gap 8, all `0xcc`); next
  0x63bcb20..0x63bcb77 (padding 14, all `0xcc`).
- Strict mnemonic lines: 212. Calls: 6 — trylock
  0x63bc8b9 -> 0x63f17b0, lock-wait 0x63bc943 -> 0x63bf680,
  bin_table_init 0x63bc9ec -> 0x63d9880, fallback helper
  0x63bca0f -> 0x63abd00, lu-miss 0x63bcafe -> 0x63d9700,
  `__stack_chk_fail` 0x63bcb0d -> 0x63f0d70. Ret: 1
  (0x63bc83e). Tail-jump exit: 1 (0x63bc93b ->
  `pthread_mutex_unlock`). Bsr: 0. Lock: 0/0. Jumps: 27,
  exactly one outside the window (the unlock tail jump).
- Bin_table_init site 0x63bc9ec: block 0x63bc9d8,
  `lea 0x20(%rsp),%rdi`, `r10`/`rsi`/`rdi` saved to
  `0x18/0x10/0x8(%rsp)` and restored, rejoin
  `jmp 0x63bc787`; entered only by the null-context `je`
  at 0x63bc781.
- Walk: top index `(key >> 0x1a) & 0xf0`, high bits
  `key & 0xffffffffc0000000`, compare `cmp %rcx,%r8` at
  0x63bc7a3, mismatch to the scan; second level
  `(key >> 0x9) & 0x1ffff8 + table + 0x8`, loaded into `rdi`
  at 0x63bc7bd.
- Extract: `shl $0x10` / `sar $0x10` + `and
  $0xffffffffffffff80`; zero path on
  `(value << 16) <= 0x7fffff` (all six outputs zeroed);
  page of node+0x10 to `*rbx`; flag path on bit 12 of the
  descriptor clear (`*r10`/`*r13`/`*r15` = 0, `*r12` = 1,
  `*r14` = 0); otherwise index `(desc >> 0x1c) & 0x3ff` to
  `*r15` and byte-indexed 40-byte-entry table field (+0x10)
  at 0x6711b40 to `*r12`.
- Index path reads the node-resolution tables 0x65096c0 and
  0x6511780 and computes the mutex node (node pointer +
  0x40).
- Trylock: `pthread_mutex_trylock@plt` at 0x63bc8b9;
  failure calls the lock-wait helper 0x63bf680 and retries;
  success updates owner/counters, computes
  `imul 0xb0(%rbx) * *r12` to `*r10`,
  `*r12 - 0x88(%rbx)` to `*r13`, and the 0xc0(%rbx) chain
  (or the fallback helper 0x63abd00) to `*r14`, then exits
  by tail jump to `pthread_mutex_unlock`.
- Scan: 8 slots, table+0x100 in `rdi`, key in `r8`; two
  reversed-operand compares (slots 3 and 6); slot 7
  memory-direct; slot-0 hit block 0x63bc96d..0x63bc99b,
  shared move-to-front block 0x63bca37.
- Lu-miss 0x63bcafe: `rdi` = `rbp` context, `rsi` =
  0x6511a00 (`.bss`, NOT entry `rsi`), `rdx` = `rdi`,
  `rcx` = entry `rsi`, `r8d` = 1, `r9d` = 0; rejoin
  `jmp 0x63bc7bd`.
- Section check (own ELF parse): `.bss` is
  0x64ffe40..0x6728924, NOBITS; both 0x6511a00 and 0x6711b40
  lie inside it, so neither has file bytes.
- Exit: `eax` = 0 at both exits (entry xor + top-index
  `and $0xf0,%eax` + epilogue canary load-and-subtract on
  both paths); no `sete`, no null-flag epilogue.
- Raw-`0xe8` census: 108 total, tiers 10x1, 8x1, 6x2, 5x1,
  4x8, 2x12, 1x17; this FDE raw 1.
- `.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`:
  278 entries, counted separately.
- Disjointness: verifier scanned 67,278 priors, 0
  skipped, NONE (deduplicated figure 66,430 after removing
  848 within-file duplicate ranges).
- 1-raw tier: 17 candidates surveyed, 16 survive, 1 excluded
  as a whole FDE (0x63adf40..0x63ae252 overlaps packet #214).
  #311's pointer for this window verified correct by program
  arithmetic and objdump census — no correction.
- Fall-through re-verified by program: 0x63c2f00..0x63c3328
  (1064B, 230 strict, 10 calls, 1 bti 0x63c30ed, 1 miss, 1 ret
  0x63c30cf, bsr 1 at 0x63c31a1, 31 jumps, tail jump 0x63c3132
  -> 0x63d72b0). It is the last surviving 1-raw candidate.

## Implementation and comparison

Not yet implemented/measured (static packet only): no Rust
reconstruction of this routine exists yet. The verifier is a
static Python checker (byte reads only); the unit tests are
tamper controls plus independent recounts and objdump
regeneration, not a reimplementation.

## Results and limitations

- Verifier: exit 0, 163 checks, 0 failures.
- Unit tests: exit 0, 12 checks, 0 failures.
- `make verify`: exit 0 (559 manifests, 7159 entries).
- `make catalogue-check`: exit 2, pre-existing failure, not a
  packet regression.
- Disjointness: verifier scanned 67,278 priors, 0 skipped,
  NONE (deduplicated figure 66,430 after removing 848
  within-file duplicate ranges).
- Unknown: the runtime contents of the `.bss` objects at
  0x6511a00 and 0x6711b40; the caller-side meaning of the entry
  key and of `r8d`/`r9d`; the semantics of the six output
  values beyond the store sites; the table entries' other
  fields besides +0x10; the mutex node field layout beyond
  the offsets the code uses.
- Next question: packet #313 decodes 0x63c2f00..0x63c3328
  (1064 bytes, 1 bin_table_init site, 1 lu-miss site, 1 ret,
  bsr 1, tail-jump exit to 0x63d72b0) — the last surviving
  1-raw candidate.
