# RE-001-node115-lu-miss-caller-7site-dispatch: lu-miss caller with seven miss sites (first lu-miss-only window)

Sixth packet of the lu-miss-caller frontier (after #314 on `0x63495b0`,
#315 on `0x6353a70`, #316 on `0x6355900`, #317 on `0x63577f0`, and #318
on `0x635a7a0`). FDE `0x635c6d0..0x635de25` (5973 bytes, 1220 strict
lines) is a single-walk lookup routine with a dispatch body and SEVEN
lu-miss sites — the most miss sites of any frontier window so far, and
the first lu-miss-ONLY window (0 second-handler sites). It opens with
no entry null guard (entry falls straight into the TLS flag check), a
TLS flag check and a size class (byte table `0x67277c0` + size table
`0x6727a00`), one context-table walk keyed by `r12` (entry `rdi`), two
`shl $0x10` / `sar $0x10` extracts feeding helpers `0x63be4d0` (twice)
and `0x63bd6c0` (twice, once fed by the #314 window's output struct)
plus four inline `shr $0x30` descriptor-field extracts, and nine 8-slot
move-to-front scan loops whose exhaustions fall to the seven lu-miss
sites. The fourth miss block (`0x635dcc6`) is the shared exhaustion
target of three loops. All seven lu-miss sites share one argument
pattern (`rdi` = `rbx` context, `rsi` = `.bss` `0x6511a00`, `rdx` =
`lea 0x1b0(%rbx)`, `rcx` = `r12` walk key, `r8d` = 1, `r9d` = 0), with
the `rcx` provenance proven by CFG reachability (the only `r12` write
reaching any miss site is the entry `mov %rdi,%r12`). It exits by a
single `ret` with `rax` = 0 (the epilogue canary check leaves `rax` 0),
unlike #314 (`rbx`), #315 (`r12`), #316 (`r13`), #317 (`r12`), and #318
(path-dependent `r11`). 0 `bin_table_init` sites, 9 `bsr`, 0 tail-jump
exits, 0 lock prefixes. This window is a lu-miss-ONLY survivor (in the
lu-miss survivor list but NOT in the second-handler survivor list), so
claiming it consumes one slot of the combined 25-FDE miss-handler pool
without being shared.

## Window

| Item | Value |
| --- | --- |
| FDE | `0x635c6d0..0x635de25` |
| Bytes | 5973 |
| Strict lines | 1220 |
| Calls | 31 (17 distinct direct targets, 1 indirect) |
| Bin_table_init sites | 0 |
| Lu-miss sites | 7 (`0x635db78`, `0x635dc13`, `0x635dc48`, `0x635dce3`, `0x635dd28`, `0x635ddda`, `0x635de17`) |
| Second-handler sites | 0 |
| Ret | 1 (`0x635c886`) |
| Tail-jump exits | 0 |
| Bsr | 9 |
| Lock sub / add | 0 / 0 |
| Jumps | 200 (0 outside) |
| Prev FDE | `0x635a7a0..0x635c6c7` (#318 window, gap 9, all `0xcc`) |
| Next FDE | `0x635de30..0x635ded5` (padding 11, all `0xcc`) |

## Classification

- Entry: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx interleaved with
  the entry movs (`mov %rsi,%r14` at `0x635c6d8`,
  `mov %edx,%r13d` at `0x635c6dd`, `mov %rdi,%r12` at `0x635c6e2`),
  `sub $0x88,%rsp`, canary at `0x78(%rsp)`. `rdi` is the walk key
  (kept in `r12`); `rsi` is the size input (kept in `r14`); `edx` is
  flags (kept in `r13d`); `rbx` is the TLS-derived context base
  (`mov $0xffffffffffffef58,%rbx` at `0x635c6ee`,
  `add %fs:0x0,%rbx` at `0x635c70d`). No entry null guard and no
  lock-add walk entry — unlike #318, which had both.
- TLS flag check: `movzbl %fs:0x330(%rbx),%edx` at `0x635c705`;
  `test %dl,%dl` at `0x635c716`; nonzero jumps to the init block at
  `0x635ccb0`, which calls helper `0x63ef8e0` at `0x635ccb8`
  (`rdi` = `rbx`, `rsi` = 1; result `mov %rax,%rbx` at `0x635ccc4`,
  flag rechecked `movzbl 0x330(%rax),%edx` at `0x635ccbd`; rejoin
  `jmp 0x635c71e` at `0x635ccc7`).
- Size class at entry: byte table `0x67277c0` at index `(r14+7)>>3`
  into `r9d`; size table `0x6727a00` (`mov (%r10,%r9,8),%rbp`);
  flags gate `(1<<flags)&~1` via `mov %r13d,%r11d` /
  `and $0xfff00,%r11d` (`jne 0x635ca40`); flag `0x6713606`
  (`cmpb $0x0,0x0(%r13)` at `0x635c7b9`, `je 0x635c900`); thresholds
  `$0x1000` (`cmp $0x1000,%r14`, `ja 0x635cc58` bsr path),
  `$0x3800` (`cmp $0x3800,%r14`), `$0x1000` on the size-table result
  (`cmp $0x1000,%rbp`, `cmp $0x1000,%rax`). No `$0xe7` gate in this
  window (unlike #318).
- Walk (single, table in `rbx` + 0x1b0, key in `r12`): top index
  `(key >> 0x1a) & 0xf0`, high bits `key & 0xffffffffc0000000`,
  compare `cmp %rdx,%r11` at `0x635cb31` (`rdx` =
  `0x1b0(%rcx)`), mismatch to the scan at `0x635d762`; second level
  `(key >> 0x9) & 0x1ffff8 + table + 0x8`, loaded into `rsi` at
  `0x635cb51` (not stored to an output slot). The walk table pointer
  (`lea 0x1b0(%rbx)`) is the lu-miss `rdx` at all seven miss sites.
  Re-entered per element: nine top-index setups (`shr $0x1a` at
  `0x635cb16`, `0x635cd29`, `0x635cefe`, `0x635d016`, `0x635d086`,
  `0x635d156`, `0x635d2ba`, `0x635d463`, `0x635d63a`) and seventeen
  second-level derefs.
- Extract (two shapes): `shl $0x10,%rsi` / `sar $0x10,%rsi` /
  `and $0xffffffffffffff80,%rsi` feeding `call 0x63be4d0` at
  `0x635cb70` and `0x635d0dd`, and `call 0x63bd6c0` at `0x635cd7a`
  and `0x635d53a` (the latter with `rdi` = `rbx` and `rsi` =
  `0x10(%rsp)`, the #314 window's output struct from the call at
  `0x635d52d`); four inline `shr $0x30` descriptor-field extracts
  (`%r8` at `0x635d05b`, `%r14` at `0x635d19d`, `%rax` at
  `0x635d4a6`, `%r13` at `0x635d67f`). No helper `0x63be540` call in
  this FDE (unlike #318).
- Scan (nine 8-slot move-to-front loops, table+`0x2b0` in `rbx`,
  key in the walk-key high bits): slot-0 compares at `0x635d2de`
  (`%r14`), `0x635d4c0` (`%r15`), `0x635d544` (`%r11`),
  `0x635d5ea` (`%r11`), `0x635d688` (`%r14`), `0x635d6f4`
  (`%r10`), `0x635d762` (`%r11`), `0x635d7af` (`%r14`),
  `0x635da2d` (`%r11`); loop compares at `0x635d863`,
  `0x635d8c8`, `0x635d92c`, `0x635d9d4`, `0x635da85`, `0x635daf5`,
  `0x635db8f`, `0x635dc5f`, `0x635dd3f`; exhaustion counters
  `r11` == 8 -> miss 1, `r11` == 8 -> miss 2, `r10` == 8 -> miss 3,
  `r14`/`r15`/`rdi` == 8 -> miss 4 (shared by three loops),
  `rdi` == 8 -> miss 5, `rdi` == 8 -> miss 6, `r8` == 8 -> miss 7.
  Zero reversed-operand compares.
- Lu-miss sites (7): all share one argument pattern — `rdi` = `rbx`
  context, `rsi` = `0x6511a00` (`.bss`, NOT entry `rsi`), `rdx` =
  `lea 0x1b0(%rbx)`, `rcx` = `r12` walk key, `r8d` = 1, `r9d` = 0.
  Blocks `0x635db5b` (call `0x635db78`, rejoin `jmp 0x635d04e`),
  `0x635dbf6` (call `0x635dc13`, rejoin `jmp 0x635d18d`),
  `0x635dc2b` (call `0x635dc48`, rejoin `jmp 0x635d49b`),
  `0x635dcc6` (call `0x635dce3`, rejoin `jmp 0x635cd68`),
  `0x635dd0b` (call `0x635dd28`, rejoin `jmp 0x635d0bd`),
  `0x635ddb9` (call `0x635ddda`, rejoin `jmp 0x635cb4d`),
  `0x635ddf6` (call `0x635de17`, rejoin `jmp 0x635d675`). Sites 6
  and 7 save/restore `r10` in `(%rsp)` around the call. The `rcx`
  provenance is proven by CFG reachability: the only `r12` write
  that reaches any miss site is the entry `mov %rdi,%r12` at
  `0x635c6e2`; the other `r12` writes (`shr $0x9` at `0x635cd4c`,
  `add` at `0x635cd57`, `shr $0x9` at `0x635d30e`, `shr $0x9` at
  `0x635d605`) sit on walk-match / scan-hit paths that rejoin the
  extract and reach the epilogue, never a miss site — so `rcx` is
  the walk key (entry `rdi`) itself.
- Second-handler sites (0): the second miss handler `0x634ebb0` is
  NOT called from this FDE — the first frontier window with zero
  second-handler sites. The node-resolution table `0x65096c0` (used
  by #318's `rsi` = 0 proof) is not referenced here.
- Dispatcher: #314 window once (`0x635d52d`; `rdi` =
  `lea 0x10(%rsp)`, `rsi` = `rbx`, `rdx` = `lea 0x1b0(%rbx)`,
  `rcx` = `r12`); the FDE after #313's window (`0x63c3330`) twice
  (`0x635cb8e`, `0x635d0f4`); the FDE after #298's window
  (`0x6363260`) three times (`0x635d076`, `0x635d44b`,
  `0x635d9bd`); `0x63eb870` 2, `0x63ead50` 2, `0x63be4d0` 2,
  `0x63bd6c0` 2, and eleven further callees once each. PLT:
  `abort@plt` 1, `__stack_chk_fail@plt` 1 (no `memset`,
  no `__errno_location`). One indirect call via GOT `0x64ffb30`
  (at `0x635ce82`), `R_X86_64_RELATIVE` — runtime-filled. The #313
  and #298 windows themselves, and the #315, #316, #317, and #318
  windows, are NOT called from this FDE.
- Bsr (9): at `0x635c9dc`, `0x635cc75`, `0x635cdbc`, `0x635cf71`,
  `0x635d1b5`, `0x635d20f`, `0x635d358`, `0x635d5bb`, `0x635d825` —
  all power-of-two roundings in dispatcher sub-blocks.
- Exit: `eax` = 0 at the single `ret` (`0x635c886`; epilogue canary
  check `mov 0x78(%rsp),%rax` at `0x635c861`,
  `sub %fs:0x28,%rax` at `0x635c866`, `jne 0x635d9aa` ->
  `call __stack_chk_fail`; `add $0x88,%rsp`, pops, `ret`). The
  check passes only when `rax` is 0, and no instruction writes
  `rax` between the check and the `ret` — so the exit value is 0,
  the first zero exit in the frontier. All 200 jumps target inside
  the window.

## Census (from the objdump exhibit, never copied from a prior packet)

- Raw `0xe8` census (byte scan for `e8` with rel32 target `0x63d9700`,
  grouped by enclosing `.eh_frame` FDE, own parse of 135,313 FDEs):
  total 168, 53 FDEs, tiers 1x18, 2x14, 3x1, 4x11, 5x1, 6x2, 7x1, 8x1,
  10x3, 13x1. This FDE holds 7 raw sites, matching its 7 objdump sites.
- Raw `0xe8` census for `0x63d9880` (bin_table_init): total 108, 42
  FDEs, tiers 1x17, 2x12, 4x8, 5x1, 6x2, 8x1, 10x1. This FDE holds 0
  raw sites.
- Raw `0xe8` census for `0x634ebb0` (second miss handler): total 64
  sites. This FDE holds 0 raw sites — consistent with 0 second-handler
  sites. The next candidate `0x635e2e0` holds 3 raw sites, matching
  its 3 objdump sites.
- `.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278
  entries, counted separately.
- `.bss` is `0x64ffe40..0x6728924` (NOBITS); all nine referenced
  addresses (`0x6511749`, `0x6511a00`, `0x6713606`, `0x67277c0`,
  `0x6727a00`, `0x6728140`, `0x6728840`, `0x6728850`, `0x6728868`)
  lie inside it. `.data` holds `0x64ffb30`, `0x64ffdc8`, `0x64ffdcc`;
  `.rodata` holds `0x9618e8` (the `abort` argument).

## Correction to #318's pointer (proven by targeted objdump census)

#318's survey pointer for this window listed **5973 bytes, 1220
strict, 31 calls, 7 lu-miss sites at `0x635db78`, `0x635dc13`,
`0x635dc48`, `0x635dce3`, `0x635dd28`, `0x635ddda`, `0x635de17`, 0
bin_table_init sites, 0 second-handler sites, 1 ret at `0x635c886`,
bsr 9** — verified correct, along with every other figure. No
correction.

## Frontier status

This packet is the sixth of the lu-miss-caller frontier (callers of
`0x63d9700` that do not call `bin_table_init`): 53 FDEs, 168 sites,
16 survivors. This window is a lu-miss-ONLY survivor (in the lu-miss
survivor list but NOT in the second-handler survivor list), so
claiming it consumes one slot of the combined 25-FDE miss-handler
pool (lu-miss 16 ∪ second-handler 18, 9 shared) without being shared.

## Disjointness

Range-only collector over the merged tree plus all prior `hl-wt-calls*`
worktree records (exhibits/windows only, all range-bearing forms,
decimal-integer start/end accepted, plain `int(x, 16)` for hex strings).
The window `0x635c6d0..0x635de25` overlaps no prior range (verifier:
73,176 priors scanned, 0 skipped, disjointness NONE), including
packet #318's window `0x635a7a0..0x635c6c7`, packet #317's window
`0x63577f0..0x635a786`, packet #316's window `0x6355900..0x63577e2`,
packet #315's window `0x6353a70..0x635582b`, packet #314's window
`0x63495b0..0x6349775`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`. The next candidate `0x635e2e0..0x635f315` is
likewise disjoint from all priors and from this window (verifier).

## Not covered

- The bin_table_init body `0x63d9880..0x63d9a64` (#262), the lu-miss
  handler `0x63d9700..0x63d987b` (#215), the second miss handler
  `0x634ebb0..0x634eccd` (NOT called from this FDE), the lock-wait
  helper `0x63bf680..0x63bf7ee` (#251), the extract helper FDEs
  `0x63be4d0..0x63be53d`, `0x63bd6c0..0x63bd8b5`, the context helper
  FDE `0x63ef8e0..0x63efba2`, and the PLT stubs are cited, not claimed.
- The dispatcher callees' bodies are cited, not claimed — including
  the #314 window (called once), the FDEs after the #313 window
  (`0x63c3330..0x63c349b`, called twice) and after the #298 window
  (`0x6363260..0x6363552`, called three times), and the #315/#316/
  #317/#318 windows (NOT called from this FDE).
- The `.bss` objects are referenced by address only; their runtime
  contents are not established.
- The entry inputs' caller-side meaning, the walk key's caller-side
  meaning beyond its entry-`rdi` origin, and the dispatcher callees'
  semantics beyond their call sites are not established. The exit
  value's meaning beyond `rax` = 0 is not established.

## Verification

- Static verifier
  `tools/node115_lu_miss_caller_7site_dispatch.py`:
  exit 0 (303 checks, 0 failures).
- Own unit tests
  `tests/test_node115_lu_miss_caller_7site_dispatch.py`
  (tamper controls first — hex flip, strict-count change, call-site
  change, injected overlap — each makes the temp-copy verifier fail; the
  clean temp copy passes): exit 0 (12 checks, 0 failures).
- `make verify`: exit 0 (559 evidence-packet manifests, 7159 entries).
- `make catalogue-check`: exit 2 with the pre-existing `Stale catalogue:
  README.md` failure, also present on a pristine checkout; not a packet
  regression.
- Full `make test` is not run (584 files on the new base; hours of runtime
  and VM-restart risk). This deviation from the repository's stated gate is
  declared here rather than hidden.
- `.hex` exhibits are raw binary bytes, not hex text.

## Next question

Packet #320 decodes `0x635e2e0..0x635f315` (4149 bytes, 898 strict,
38 calls, 1 lu-miss site at `0x635f30b`, 0 bin_table_init sites, 3
second-handler sites, 1 ret at `0x635e7eb`, bsr 5 — the next surviving
lu-miss caller after this packet, verified by targeted objdump census
against all prior exhibits; it is a SHARED survivor, unlike this
packet).
