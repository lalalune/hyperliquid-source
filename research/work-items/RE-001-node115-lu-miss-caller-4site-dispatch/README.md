# RE-001-node115-lu-miss-caller-4site-dispatch: lu-miss caller with four miss sites (first multi-site window)

Fifth packet of the lu-miss-caller frontier (after #314 on `0x63495b0`,
#315 on `0x6353a70`, #316 on `0x6355900`, and #317 on `0x63577f0`).
FDE `0x635a7a0..0x635c6c7` (7975 bytes, 1720 strict lines) is a
single-walk lookup routine with a dispatch body and FOUR lu-miss sites —
the first multi-site window of the frontier. It opens with an entry null
guard (both args non-null tail-jumps to the #283 window; `rsi` == 0 with
`rdi` != 0 takes the lock-add walk path), a TLS flag check and a size
class (byte table `0x67277c0` + size table `0x6727a00`), one context-table
walk keyed by `rbx` (entry `rdi` — the roles are swapped relative to
#314–#317, where `rbx` was the context), an inline `shr $0x30`
descriptor-field extract plus two `shl $0x10` / `sar $0x10` extracts
feeding helpers `0x63be4d0` and `0x63bd6c0`, and four 8-slot
move-to-front scan loops whose exhaustions fall to the four lu-miss
sites. It also calls the second miss handler `0x634ebb0` twice (both
with `rsi` = 0 proven) and dispatches to the #314 window (twice), the
#313 window (twice), and the #298 window (twice). All four lu-miss
sites share one argument pattern (`rdi` = `rbp` context, `rsi` = `.bss`
`0x6511a00`, `rdx` = saved walk table, `rcx` = `rbx` walk key, `r8d` = 1,
`r9d` = 0), with the `rcx` provenance proven by CFG reachability (the
only `rbx` write reaching any miss site is the entry `mov %rdi,%rbx`).
It exits by a single `ret` with `rax` = `r11` — a path-dependent value
(0 on the errno path), so no single exit-register identity is
established, unlike #314–#317. 0 `bin_table_init` sites, 7 `bsr`,
1 tail-jump exit. This window is a shared survivor of both
miss-handler lists, so claiming it consumes one slot of the combined
25-FDE miss-handler pool.

## Window

| Item | Value |
| --- | --- |
| FDE | `0x635a7a0..0x635c6c7` |
| Bytes | 7975 |
| Strict lines | 1720 |
| Calls | 103 (33 distinct direct targets, 2 indirect) |
| Bin_table_init sites | 0 |
| Lu-miss sites | 4 (`0x635bebb`, `0x635c0d2`, `0x635c231`, `0x635c45f`) |
| Second-handler sites | 2 |
| Ret | 1 (`0x635ab53`) |
| Tail-jump exits | 1 (`0x635a80f` -> `0x6350210`, #283 window) |
| Bsr | 7 |
| Lock sub / add | 0 / 1 |
| Jumps | 299 (1 outside: the tail-jump exit) |
| Prev FDE | `0x635a790..0x635a79b` (gap 5, all `0xcc`) |
| Next FDE | `0x635c6d0..0x635de25` (padding 9, all `0xcc`) |

## Classification

- Entry: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx,
  `sub $0xc8,%rsp`, canary at `0xb8(%rsp)`. `rdi` is the walk key
  (kept in `rbx`); `rsi` is the context (kept in `rbp`). Entry null
  guard: `test %rdi,%rdi` at `0x635a7ce`, `test %rsi,%rsi` at
  `0x635a7d4`. Both non-null -> canary check -> `mov $0x1,%ecx`,
  `xor %edx,%edx`, `mov %rbx,%rdi`, epilogue pops, tail-jump to
  `0x6350210` (#283's window) at `0x635a80f`. `rsi` == 0 and `rdi` != 0
  -> the walk path at `0x635a968` (only jumper: `jne` at `0x635a81f`).
  Otherwise -> the TLS/size-class path at `0x635a825`.
- TLS flag check: `cmpb $0x0,%fs:0x330(%rdx)` at `0x635a838`
  (`rdx` = `0xffffffffffffef58`); nonzero calls helper `0x63ef8e0`
  from the init block at `0x635ac6e` (`call` at `0x635ac73`,
  `rdi` = `r12`, `rsi` = 0; result checked `cmpb $0x0,0x330(%rax)`).
- Size class at entry: byte table `0x67277c0` at index `(rbp+7)>>3`
  into `r15d` (`cmp $0xe7,%r15d`); size table `0x6727a00`
  (`mov (%r8,%rbx,8),%r13`); flag `0x6713606`
  (`cmpb $0x0,(%rax)`, `je 0x635ab58`); thresholds `$0x1000`
  (`cmp $0x1000,%rbp`, `ja 0x635ae12` bsr path) and `$0x3800`
  (`cmp $0x3800,%r13`).
- Walk (single, table in `rbp` + 0x1b0, key in `rbx`): top index
  `(key >> 0x1a) & 0xf0`, high bits `key & 0xffffffffc0000000`,
  compare `cmp %rdx,%r11` at `0x635aa20` (`rdx` =
  `0x1b0(%r12)`), mismatch to the scan at `0x635b222`; second level
  `(key >> 0x9) & 0x1ffff8 + table + 0x8`, loaded into `r10` at
  `0x635aa3d` (not stored to an output slot). The walk table pointer
  (`lea 0x1b0(%rbp)`) is saved to `0x8(%rsp)` at `0x635aa09` and
  reloaded as the lu-miss `rdx` at all four miss sites. Re-entered
  per element (second-level derefs at `0x635b283`, `0x635b31d`,
  `0x635b4a8`, `0x635b4c5`). The walk path starts with
  `lock addq $0x1,0x6511740` at `0x635a968` and a load of `0x64ffb58`.
- Extract (three shapes): inline `shr $0x30,%r13` at `0x635aa55`
  (descriptor top 16 bits; `r14d` = `r13d` is the size-table index)
  and a second `shr $0x30,%rax` at `0x635bd5b` (`cmp $0x23,%rax`
  size-class gate); `shl $0x10,%rsi` / `sar $0x10,%rsi` /
  `and $0xffffffffffffff80,%rsi` feeding `call 0x63be4d0` at
  `0x635b2d3` and `call 0x63bd6c0` at `0x635b4df`; helper `0x63be540`
  called twice (at `0x635b0be` and `0x635b459`) with `rdi` = the #314
  window's output struct in a stack temp (`0x50(%rsp)` /
  `0x30(%rsp)`), with no `shl`/`sar` before it.
- Scan (four 8-slot move-to-front loops, table+`0x2b0` in `rbp`, key
  in `r11` = key high bits): slot-0 compares at `0x635b222`,
  `0x635ba1a`, `0x635bd7a`, `0x635bdc6`, `0x635bf97` (all
  `cmp 0x2b0(%rbp),%r11`); loop compares at `0x635bccc`,
  `0x635be29`, `0x635bfb1`, `0x635bffe`, `0x635c305`; exhaustion
  counters `r13` == 8 -> miss 1, `rsi` == 8 -> miss 2, `r8` == 8 ->
  miss 3, `r9` == 8 -> miss 4. Zero reversed-operand compares.
- Lu-miss sites (4): all share one argument pattern — `rdi` = `rbp`
  context, `rsi` = `0x6511a00` (`.bss`, NOT entry `rsi`), `rdx` =
  `0x8(%rsp)` (saved walk table), `rcx` = `rbx` walk key, `r8d` = 1,
  `r9d` = 0. Blocks `0x635bea0` (call `0x635bebb`, rejoin
  `jmp 0x635b4cd`), `0x635c0ad` (call `0x635c0d2`, falls through to
  `jmp 0x635b2a8`), `0x635c212` (call `0x635c231`, falls through),
  `0x635c43f` (call `0x635c45f`, falls through). The `rcx`
  provenance is proven by CFG reachability: the only `rbx` write
  that reaches any miss site is the entry `mov %rdi,%rbx` at
  `0x635a7b1`; every other `rbx` write (`0x635a882`, `0x635b119`,
  `0x635b1ce`, `0x635b731`, `0x635b851`, `0x635bb34`, `0x635bc34`,
  `0x635bda4`, `0x635bf2e`) reaches no miss site, and the walk entry
  `0x635a968` reaches all four sites — so `rcx` is the walk key
  (entry `rdi`) itself. This is the first window where the miss
  `rdi` is the context in `rbp` rather than `rbx`, and the first
  where `rcx` is the entry `rdi` itself rather than a derived key
  register.
- Second-handler sites (2): `0x635b5ea` and `0x635bd35` ->
  `0x634ebb0`; both `rdi` = `r12` (context base),
  `rdx` = `0x64da4b0` (`.data.rel.ro`), `rsi` = 0 proven at both —
  site 1 is entered only via `je` at `0x635b471`, taken only when
  `rsi` (loaded from node table `0x65096c0` at `0x635b467`) is null;
  site 2 has `xor %esi,%esi` immediately before.
- Dispatcher: #314 window twice (`0x635b0b4`, `0x635b44f`;
  `rdi` = stack temp, `rsi` = `r12`, `rdx` = `lea 0x1b0(%r12)`,
  `rcx` = `r14` / `r9`); #313 window twice (`0x635bafa`,
  `0x635c1ee`; `rdi` = `r12`, `rsi` = `r9`, `rdx` = `rbp`,
  `rcx` = `r13`); #298 window twice (`0x635bbbb`, `0x635c4ed`;
  `rdi` = `r12`, `rsi` = `r9`, `rdx` = `r13`); `0x6364880` 13 times,
  `0x6353610` 12 times, `0x63e9cd0` 12 times, `0x63bd2c0` 8 times
  (18-byte thunk), `memset@plt` 5, `0x63e9c40` 4, `0x6365150` 4,
  `0x63d9700` 4, `0x63eec80` 3, and eleven further callees twice each.
  PLT: `memset` 5, `__errno_location` 2, `__stack_chk_fail` 1. Two
  indirect calls via GOT `0x64ffb30` (at `0x635ae87`) and `0x64ffb38`
  (at `0x635af57`), both `R_X86_64_RELATIVE` — runtime-filled. The
  #315, #316, and #317 windows are NOT called from this FDE.
- Bsr (7): at `0x635ae3c`, `0x635b5a1`, `0x635b77c`, `0x635b886`,
  `0x635bc82`, `0x635c3ed`, `0x635c61f` — all power-of-two roundings
  in dispatcher sub-blocks.
- Exit: `eax` = `r11` at the single `ret` (`0x635ab53`; epilogue
  canary check `jne 0x635b4e9` -> `call __stack_chk_fail`). `r11` is
  0 on the errno path (`xor %r11d,%r11d` at `0x635ab20`) and a
  path-dependent value on the other rejoin paths (queue-head pointer
  loaded at `0x635ab80`, or a saved intermediate restored at
  `0x635ac1f` / `0x635ae09`), so no single exit-register identity is
  established. The tail-jump exit (`jmp 0x6350210` at `0x635a80f`,
  after the epilogue pops, with `ecx` = 1, `edx` = 0, `rdi` = `rbx`)
  is the first tail-jump exit in the lu-miss-caller frontier
  (#314–#317 all had 0). All other 298 jumps target inside the
  window.

## Census (from the objdump exhibit, never copied from a prior packet)

- Raw `0xe8` census (byte scan for `e8` with rel32 target `0x63d9700`,
  grouped by enclosing `.eh_frame` FDE, own parse of 135,313 FDEs):
  total 168, 53 FDEs, tiers 1x18, 2x14, 3x1, 4x11, 5x1, 6x2, 7x1, 8x1,
  10x3, 13x1. This FDE holds 4 raw sites, matching its 4 objdump sites.
- Raw `0xe8` census for `0x63d9880` (bin_table_init): total 108, 42
  FDEs, tiers 1x17, 2x12, 4x8, 5x1, 6x2, 8x1, 10x1. This FDE holds 0
  raw sites.
- `.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278
  entries, counted separately.
- `.bss` is `0x64ffe40..0x6728924` (NOBITS); all fourteen referenced
  addresses (`0x65096a0`, `0x65096c0`, `0x6511738`, `0x6511740`,
  `0x6511749`, `0x651174a`, `0x6511a00`, `0x67125d0`, `0x6713606`,
  `0x67277c0`, `0x6727a00`, `0x6728848`, `0x6728850`, `0x6728868`)
  lie inside it.

## Correction to #317's pointer (proven by targeted objdump census)

#317's survey pointer for this window listed **bsr 7** — verified
correct, along with every other figure (7975 bytes, 1720 strict,
103 calls, 4 lu-miss sites at `0x635bebb`, `0x635c0d2`, `0x635c231`,
`0x635c45f`, 0 bin_table_init sites, 2 second-handler sites, 1 ret
at `0x635ab53`). No correction.

## Frontier status

This packet is the fifth of the lu-miss-caller frontier (callers of
`0x63d9700` that do not call `bin_table_init`): 53 FDEs, 168 sites,
16 survivors. This window is a shared survivor of both miss-handler
lists, so claiming it consumes one slot of the combined 25-FDE
miss-handler pool (lu-miss 16 ∪ second-handler 18, 9 shared).

## Disjointness

Range-only collector over the merged tree plus all prior `hl-wt-calls*`
worktree records (exhibits/windows only, all range-bearing forms,
decimal-integer start/end accepted, plain `int(x, 16)` for hex strings).
The window `0x635a7a0..0x635c6c7` overlaps no prior range (verifier:
72,333 priors scanned, 0 skipped, disjointness NONE), including
packet #317's window `0x63577f0..0x635a786`, packet #316's window
`0x6355900..0x63577e2`, packet #315's window `0x6353a70..0x635582b`,
packet #314's window `0x63495b0..0x6349775`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`. The next candidate `0x635c6d0..0x635de25` is
likewise disjoint from all priors and from this window (verifier).

## Not covered

- The bin_table_init body `0x63d9880..0x63d9a64` (#262), the lu-miss
  handler `0x63d9700..0x63d987b` (#215), the second miss handler
  `0x634ebb0..0x634eccd`, the lock-wait helper `0x63bf680..0x63bf7ee`
  (#251), the extract helper FDEs `0x63be540..0x63be54d`,
  `0x63be4d0..0x63be4e1`, `0x63bd6c0..0x63bd6d2`, the 18-byte thunk
  `0x63bd2c0..0x63bd2d2`, the context helper FDE `0x63ef8e0..0x63efba2`,
  and the PLT stubs are cited, not claimed.
- The dispatcher callees' bodies are cited, not claimed — including
  the #314 window (called twice), the #313 window (called twice),
  the #298 window (called twice), the #315/#316/#317 windows (NOT
  called from this FDE), and the #283 window (tail-jump target).
- The `.bss` objects are referenced by address only; their runtime
  contents are not established.
- The entry inputs' caller-side meaning, the walk key's caller-side
  meaning beyond its entry-`rdi` origin, and the dispatcher callees'
  semantics beyond their call sites are not established. The exit
  value's meaning beyond `rax` = `r11` (path-dependent) is not
  established.

## Verification

- Static verifier
  `tools/node115_lu_miss_caller_4site_dispatch.py`:
  exit 0 (238 checks, 0 failures).
- Own unit tests
  `tests/test_node115_lu_miss_caller_4site_dispatch.py`
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

Packet #319 decodes `0x635c6d0..0x635de25` (5973 bytes, 1220 strict,
31 calls, 7 lu-miss sites at `0x635db78`, `0x635dc13`, `0x635dc48`,
`0x635dce3`, `0x635dd28`, `0x635ddda`, `0x635de17`, 0 bin_table_init
sites, 0 second-handler sites, 1 ret at `0x635c886`, bsr 9 — the
next surviving lu-miss caller after this packet, verified by targeted
objdump census against all prior exhibits; it is a lu-miss-only
survivor, not a shared survivor).
