# RE-001-node115-lu-bintableinit-caller-1site-1walk-extract-sizeclass: single-walk lookup-with-extract size-class caller

- Component ID: RE-001-node115-lu-bintableinit-caller-1site-1walk-extract-sizeclass
- Target release and full SHA-256: node #115 only,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  105,896,032 bytes
- Source commit / reference commit: upstream main
  05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly census + static verifier);
  the `.bss` contents at 0x6511a00 / 0x67125f0 / 0x6713601 /
  0x6713620 / 0x6713d60 / 0x6717690 / 0x67277c0 are unresolved (not in
  the file) and are claimed only as referenced addresses; the
  extract helper, init-guard helper, helpers 0x63d6690/0x63d6880,
  lock-wait helper, and mutex node fields are claimed only as the
  code uses them
- Scope included and excluded: FDE 0x63c2f00..0x63c3328 only (1064
  bytes, 230 strict lines). Excluded: bin_table_init body
  0x63d9880..0x63d9a64 (#262), lu-miss handler 0x63d9700..0x63d987b
  (#215), extract helper FDE 0x63be550..0x63be5be, init-guard
  helper FDE 0x63d7bd0..0x63d7c32, helper FDEs 0x63d6690..0x63d66ad
  and 0x63d6880..0x63d6cb9, lock-wait helper 0x63bf680..0x63bf7ee
  (#251), tail-jump target FDE 0x63d72b0..0x63d7367, prev/next
  FDEs, PLT stubs, and the runtime contents of the seven `.bss`
  objects.

## Reproduce

Working directory: a worktree of lalalune/hyperliquid-source at
upstream main 05bc2de303c05525b71e7e257426e741bc66a390
(`~/workspace/hl-wt-calls313-115`, branch
`codex/re-004-calls313-115`).

- `python3 tools/node115_bintableinit_caller_1walk_extract_sizeclass_1site.py`
  (exit 0, 191 checks, 0 failures).
- `python3 tests/test_node115_bintableinit_caller_1walk_extract_sizeclass_1site.py`
  (exit 0, 12 checks, 0 failures).
- `make verify` (exit 0, 559 manifests, 7159 entries).
- `make catalogue-check` (exit 2, pre-existing `Stale catalogue:
  README.md`, also on a pristine checkout).
- Objump exhibit regeneration: `objdump -d
  --start-address=0x63c2f00 --stop-address=0x63c3328
  artifacts/node/115/hl-node` (matches the exhibit; the unit
  tests re-run this).
- No execution of the node binary anywhere in this packet; byte
  reads only. Full `make test` not run (584 files; declared
  deviation, see README).

## Evidence

- FDE bounds from an own `.eh_frame` parse (135,313 FDEs, sorted
  before bisect): target 0x63c2f00..0x63c3328 (1064 bytes); prev
  0x63c2e80..0x63c2f00 (gap 0); next 0x63c3330..0x63c349b
  (padding 8, all `0xcc`).
- Strict mnemonic lines: 230. Calls: 10 — extract helper
  0x63c2fa3 -> 0x63be550, trylock 0x63c2fd7 -> 0x63f17b0,
  helper 0x63c3068 -> 0x63d6690, unlock 0x63c3086 -> 0x63f0b70,
  init-guard helper 0x63c30d0 -> 0x63d7bd0, bin_table_init
  0x63c30ed -> 0x63d9880, helper 0x63c314c -> 0x63d6880,
  lock-wait 0x63c3163 -> 0x63bf680, lu-miss 0x63c3319 ->
  0x63d9700, `__stack_chk_fail` 0x63c3323 -> 0x63f0d70. Ret: 1
  (0x63c30cf). Tail-jump exit: 1 (0x63c3132 ->
  0x63d72b0). Bsr: 1 (0x63c31a1). Lock: 0/0. Jumps: 31,
  exactly one outside the window (the tail jump).
- Init guard (first in the 1-raw chain): `cmpb $0x0,0x67125f0`
  at 0x63c2f37; nonzero calls helper 0x63d7bd0 at 0x63c30d0,
  then re-leas the table base and rejoins the walk at
  0x63c2f54 (or falls through to the bin_table_init block
  when the context is null).
- Bin_table_init site 0x63c30ed: block 0x63c30e5,
  `lea 0x10(%rsp),%r15`, `mov %r15,%rdi`, no save/restore
  (block is exactly lea/mov/call/jmp), rejoin
  `jmp 0x63c2f54`; entered only by the null-context `je`
  at 0x63c2f4e plus fall-through from the init-guard path.
- Walk: top index `(key >> 0x1a) & 0xf0`, high bits
  `key & 0xffffffffc0000000`, compare `cmp %rdi,%rcx` at
  0x63c2f70, mismatch to the scan; second level
  `(key >> 0x9) & 0x1ffff8 + table + 0x8`, loaded into `r12`
  at 0x63c2f8b.
- Extract: `shl $0x10` / `sar $0x10` + `and
  $0xffffffffffffff80` on `r12`, then `mov %r12,%rdi` and
  `call 0x63be550` at 0x63c2fa3 (rsi = entry r8, rdx = entry
  rdx). No inline output decoding in this FDE.
- Size class (first in the 1-raw chain): `cmp $0x1000,%r13`,
  `ja 0x63c3178`; small path reads byte table 0x67277c0 at
  index `(r13+7)>>3` into 0x8(%rsp); bsr path (`bsr` at
  0x63c31a1, threshold 0x7000000000000000) computes the class
  into 0x8(%rsp); huge path stores `0xe8` to 0x8(%rsp).
  The class is consumed as `r8d` at 0x63c2ff8 and as `esi`
  at 0x63c3117.
- Trylock: `pthread_mutex_trylock@plt` at 0x63c2fd7 (mutex =
  `*(*rbx)+0x40`); failure calls the lock-wait helper
  0x63bf680 and retries; success updates owner/counters,
  runs the size-class vector update (tables 0x6713620 /
  0x6713d60, `paddq` into `*rbx` 0x20..0x5f, flag byte
  0x6713601 gates the 0x40/0x50 update), calls helper
  0x63d6690, saves its return byte to 0xf(%rsp), then calls
  `pthread_mutex_unlock@plt` at 0x63c3086 (inside the
  window). A nonzero helper result calls helper 0x63d6880
  at 0x63c314c before the exit-flag check.
- Exit flag byte 0x6717690: zero -> `ret` at 0x63c30cf;
  nonzero -> tail jump 0x63c3132 -> 0x63d72b0 (rdi = rbp
  context, rsi = size class, rdx = r14).
- Scan: 8 slots, table+0x100 in `r15`, key in `rcx`; two
  reversed-operand compares (slots 5 and 6); slot 7
  memory-direct; slot-0 hit block 0x63c31e9..0x63c3218,
  shared move-to-front block 0x63c323f.
- Lu-miss 0x63c3319: `rdi` = `rbp` context, `rsi` =
  0x6511a00 (`.bss`, NOT entry `rsi`), `rdx` = `r15`,
  `rcx` = entry `rsi` (r12 holds the entry key on the miss
  path — exact write-set check in the verifier), `r8d` = 1,
  `r9d` = 0; rejoin `jmp 0x63c2f8b`.
- Section check (own ELF parse): `.bss` is
  0x64ffe40..0x6728924, NOBITS; all seven referenced
  addresses (0x6511a00, 0x67125f0, 0x6713601, 0x6713620,
  0x6713d60, 0x6717690, 0x67277c0) lie inside it, so none
  has file bytes.
- Exit: `eax` = 0 at both exits (entry xor + top-index
  `and $0xf0,%eax` + epilogue canary load-and-subtract on
  both paths); no `sete`, no null-flag epilogue.
- Raw-`0xe8` census: 108 total, tiers 10x1, 8x1, 6x2, 5x1,
  4x8, 2x12, 1x17; this FDE raw 1.
- `.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`:
  278 entries, counted separately.
- Disjointness: verifier scanned 68,120 priors, 0
  skipped, NONE (deduplicated figure 67,262 after removing
  858 within-file duplicate ranges).
- 1-raw tier: 17 candidates surveyed, 16 survive, 1 excluded
  as a whole FDE (0x63adf40..0x63ae252 overlaps packet #214).
  #312's pointer for this window verified correct by program
  arithmetic and objdump census — no correction.
- Multi-raw tiers re-surveyed by this packet (own `.eh_frame`
  parse + raw-`0xe8` census + prior-exhibit overlap check over
  68,120 prior range entries): all 25 multi-raw FDEs already
  claimed (2-raw 12, 4-raw 8, 5-raw 1, 6-raw 2, 8-raw 1,
  10-raw 1). The bin_table_init caller survey is complete;
  no verified next candidate exists.
- Fall-through re-verified by program: none — this window is
  the last surviving 1-raw candidate and the multi-raw tiers
  hold no survivors.

## Implementation and comparison

Not yet implemented/measured (static packet only): no Rust
reconstruction of this routine exists yet. The verifier is a
static Python checker (byte reads only); the unit tests are
tamper controls plus independent recounts and objdump
regeneration, not a reimplementation.

## Results and limitations

- Verifier: exit 0, 191 checks, 0 failures.
- Unit tests: exit 0, 12 checks, 0 failures.
- `make verify`: exit 0 (559 manifests, 7159 entries).
- `make catalogue-check`: exit 2, pre-existing failure, not a
  packet regression.
- Disjointness: verifier scanned 68,120 priors, 0 skipped,
  NONE (deduplicated figure 67,262 after removing 858
  within-file duplicate ranges).
- Unknown: the runtime contents of the seven `.bss` objects; the
  caller-side meaning of the entry key and of `r8d`/`r9d`; the
  semantics of the extract helper 0x63be550's outputs beyond the
  call site; the size-class table's and vector tables' contents;
  the mutex node field layout beyond the offsets the code uses.
- Next question: NONE VERIFIED. The 1-raw tier is exhausted
  (16 built #298–#313 + 1 excluded = 17) and all 25 multi-raw
  caller FDEs are already claimed by packets #275–#297. The
  bin_table_init caller survey is complete (42 FDEs, 108 raw
  sites). The next packet needs a new frontier, not yet surveyed.
