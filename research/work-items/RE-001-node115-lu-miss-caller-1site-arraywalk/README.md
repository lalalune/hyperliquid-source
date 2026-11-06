# RE-001-node115-lu-miss-caller-1site-arraywalk: lu-miss caller with a single array-walk miss site (first window with reversed-operand scan compares)

Seventh packet of the lu-miss-caller frontier (after #314 on `0x63495b0`,
#315 on `0x6353a70`, #316 on `0x6355900`, #317 on `0x63577f0`, #318 on
`0x635a7a0`, and #319 on `0x635c6d0`). FDE `0x635e2e0..0x635f315` (4149
bytes, 898 strict lines) is a single-walk lookup routine with a dispatch
body and ONE lu-miss site — the seventh frontier window, and the first
with reversed-operand scan compares (four of them, slots 1, 2, 4, 5).
It opens with no entry null guard (entry falls straight into the TLS
flag check), a TLS flag check and a size class (byte table `0x67277c0`
+ size table `0x6727a00`), one context-table walk that iterates the
input array element by element (key = `*rbp` in `rcx`), one `shl $0x10`
/ `sar $0x10` extract feeding helper `0x63be540`, and a single 8-slot
move-to-front scan whose exhaustion falls to the lu-miss site. The
lu-miss call takes `rdi` = `rbx` context, `rsi` = `.bss` `0x6511a00`,
`rdx` = `lea 0x1b0(%rbx)`, `rcx` = the element key (provenance proven
by reaching-definitions: the only `rcx` definition reaching the call
is the walk-head load at `0x635ebb8`), `r8d` = 1, `r9d` = 0. It also
calls the second miss handler three times (with three different `rsi`
provenances: a computed node index, 0, and a `sched_getcpu()` result)
and the #317 window once. It exits by a single `ret` with `rax` =
`r15` (the element count) — the fourth distinct exit register in the
frontier after #314 (`rbx`), #315 (`r12`), #316 (`r13`), #317 (`r12`),
#318 (path-dependent `r11`), and #319 (0). 0 `bin_table_init` sites,
5 `bsr`, 0 tail-jump exits, 0 lock prefixes, 15 `memset@plt` calls in
an unrolled slot-clear loop. This window is a SHARED survivor (in both
the lu-miss survivor list and the second-handler survivor list), so
claiming it consumes one slot of the combined 25-FDE miss-handler pool.

## Window

| Item | Value |
| --- | --- |
| FDE | `0x635e2e0..0x635f315` |
| Bytes | 4149 |
| Strict lines | 898 |
| Calls | 38 (21 distinct direct targets, 0 indirect) |
| Bin_table_init sites | 0 |
| Lu-miss sites | 1 (`0x635f30b`) |
| Second-handler sites | 3 (`0x635ec8d`, `0x635ef3e`, `0x635f24d`) |
| Ret | 1 (`0x635e7eb`) |
| Tail-jump exits | 0 |
| Bsr | 5 |
| Lock sub / add | 0 / 0 |
| Jumps | 131 (0 outside) |
| Prev FDE | `0x635e1a0..0x635e2de` (gap 2, all `0xcc`) |
| Next FDE | `0x635f320..0x635f334` (padding 11, all `0xcc`) |

## Classification

- Entry: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx interleaved with
  the entry movs (`mov %rdx,%r9` at `0x635e2e6`,
  `mov %ecx,%r8d` at `0x635e2e9`), `sub $0xa8,%rsp`, canary at
  `0x98(%rsp)`. `rdi` is the input array base (saved `0x18(%rsp)` at
  `0x635e304`); `rsi` is the element count (saved `(%rsp)` at
  `0x635e309`); `rdx` is kept in `r9`; `ecx` is kept in `r8d`; `rbx`
  is the TLS-derived context base (`mov $0xffffffffffffef58,%rax`
  at `0x635e31e`, `add %rax,%r11` at `0x635e325`, `rbx` = `r11`
  after the init block). No entry null guard and no lock-add walk
  entry.
- TLS flag check: `cmpb $0x0,%fs:0x330(%rax)` at `0x635e328`;
  `jne 0x635ecb7` at `0x635e330` to the init block, which calls
  helper `0x63ef8e0` at `0x635ecc5` (`rdi` = `r11`, `rsi` = 0;
  result `mov %rax,%r11` at `0x635ecd7`; `jne 0x635e336` at
  `0x635ecda`). `cmpb $0x0,0x1(%r11)` at `0x635e336`;
  `jg 0x635ece0` at `0x635e33b` (the zero-result exit).
- Size class at entry: byte table `0x67277c0` at index `(r9+7)>>3`
  into `r10d` (`lea 0x7(%r9),%rsi`, `shr $0x3,%rsi`,
  `movzbl 0x0(%rbp,%rsi,1),%r10d`); size table `0x6727a00`
  (`mov (%rdi,%r10,8),%rax`); the size-table result is bounds-checked
  against `movabs $0x6fffffffffffffff,%r12` (`sub $0x1,%rax`,
  `cmp %rax,%r12`, `jb 0x635ece0`); the byte-table value is re-read
  into `0x38(%rsp)` (`mov 0x8(%rsp),%rsi`, `lea 0x67277c0,%rbp`,
  `add $0x7,%rsi`, `shr $0x3,%rsi`, `movzbl`,
  `mov %r10d,0x38(%rsp)`); flag `0x6713606` (`lea` at `0x635e4f3`,
  `movzbl (%r11),%r11d`); size-class index bound `cmp $0x23,%r13d`
  (`ja 0x635f16b`); thresholds `$0x1000` (`cmp $0x1000,%r9`,
  `ja 0x635f0a7` bsr path) and `$0x1000` on the size-table result
  (`cmpq $0x1000,0x8(%rsp)`, `ja 0x635f179` bsr path). No `$0xe7`
  gate in this window (unlike #318).
- Walk (single, table in `rbx` + 0x1b0, key = element `*rbp` in
  `rcx`): the walk iterates `rbp` from `0x40(%rsp)` (`&array[r15]`)
  to `r13` = array base + 8 * (`r15` + `r9`)
  (`lea (%rax,%r8,8),%r13` at `0x635ebad`); top index
  `(key >> 0x1a) & 0xf0`, high bits `key & 0xffffffffc0000000`,
  compare `cmp %rdi,%r10` at `0x635ebdd` (`rdi` =
  `0x1b0(%rsi)`), mismatch to the scan at `0x635ecf0`; second level
  `(key >> 0x9) & 0x1ffff8 + table + 0x8`, loaded into `rdi` at
  `0x635ebf9` (feeds the extract). The walk table pointer
  (`lea 0x1b0(%rbx)`) is the lu-miss `rdx` at the miss site.
- Extract (one shape): `shl $0x10,%rdi` / `sar $0x10,%rdi` /
  `and $0xffffffffffffff80,%rdi` feeding `call 0x63be540` at
  `0x635ec0c`; loop-back `cmp %r13,%rbp` / `jne 0x635ebb8`. No
  inline `shr $0x30` extracts; no helper `0x63be4d0` or `0x63bd6c0`
  calls in this FDE (unlike #319).
- Scan (single 8-slot move-to-front, table+`0x2b0` in `rbx`, key in
  `r10`): slot-0 compare `cmp %r8,%r10` at `0x635ecf7` (`r8` =
  `0x2b0(%rbx)` loaded at `0x635ecf0`), mismatch `jne 0x635f0ed`;
  slot-0 hit block at `0x635ed00` swaps the 16-byte entries at
  `0x2b0`/`0x2b8` and the `0x1b0`/`0x1b8` table entries, rejoining
  at `0x635ebf9`; slots 1-7 share the loop block at `0x635f0ed`
  (slot 1 `cmp %r10,%r11` at `0x635f0fc`, slot 2 `cmp %r10,%r8` at
  `0x635f1f6`, slot 3 `cmp %rax,%r10` at `0x635f272`, slot 4
  `cmp %r10,%r8` at `0x635f282`, slot 5 `cmp %r10,%r11` at
  `0x635f2b1`, slot 6 `cmp %r8,%r10` at `0x635f2c1`, slot 7
  `cmp 0x320(%rbx),%r10` at `0x635f2e4`); hits go to the shared
  MTF swap at `0x635f105` (rejoin `jmp 0x635ebf9` at `0x635f166`);
  exhaustion (slot-7 compare not taken) falls through to the miss
  block at `0x635f2f1`. FOUR reversed-operand compares (slots 1, 2,
  4, 5 — key first, table value second) — the first frontier window
  with any; #314-#319 all had 0.
- Lu-miss site (1): block `0x635f2f1` (call `0x635f30b`, rejoin
  `jmp 0x635ebf9` at `0x635f310`): `rdi` = `rbx` context, `rsi` =
  `0x6511a00` (`.bss`, NOT entry `rsi`), `rdx` =
  `lea 0x1b0(%rbx)`, `rcx` = the element key, `r8d` = 1, `r9d` = 0.
  The `rcx` provenance is proven by reaching-definitions over the
  window CFG (noreturn PLT calls terminal; `cmov` a conditional
  def): the only `rcx` definition reaching the call is the
  walk-head load `mov 0x0(%rbp),%rcx` at `0x635ebb8`. The
  `shr $0x9,%rcx` at `0x635ebe6` sits on the walk-match path and is
  killed by the reload at the loop head; every call between the
  load and the miss is on a path that reloads `rcx` first.
- Second-handler sites (3): all `rdi` = `rbx`, `rdx` =
  `lea 0x64da4b0` (`.data.rel.ro`), with three different `rsi`
  values, each proven by reaching-definitions: site 1 at
  `0x635ec8d` (`rsi` = node index `((0x50(%rsp) >> 0x14) - 1)` via
  `lea -0x1(%rcx),%esi` at `0x635ec66`; the node-table load at
  `0x635ec69` is null-tested before the call); site 2 at `0x635ef3e`
  (`rsi` = 0 via `xor %esi,%esi` at `0x635ef34`); site 3 at
  `0x635f24d` (`rsi` = `sched_getcpu()` result, adjusted by the
  count-halving at `0x635e87b`-`0x635e88b`: the reaching definitions
  are exactly `mov %eax,%esi` at `0x635e877`, `sub %r9d,%esi` at
  `0x635e885`, and `cmovb %eax,%esi` at `0x635e88b`).
- Dispatcher: #317 window once (`0x635e799`; `rdi` =
  `0x48(%rsp)` = entry `rdx`, `rsi` = `0x50(%rsp)` = entry `ecx`;
  result null-tested, stored at `array[r15]`, `r15` incremented,
  loop until `r15` == entry `rsi`); `memset@plt` 15 times (an
  unrolled 7-way slot-clear loop at `0x635e95d`-`0x635eb54` plus a
  second clear loop at `0x635eae6`-`0x635eb54`); `memcpy@plt` once
  (`0x635e63a`); `sched_getcpu@plt` once (`0x635e867`);
  `abort@plt` once (`0x635f1d2`); `__stack_chk_fail@plt` once
  (`0x635f29a`); `0x63edf10` twice (`0x635efa1`, `0x635f053`); and
  eleven further callees once each (`0x6352fc0`, `0x6360ed0`,
  `0x6362910`, `0x6364400`, `0x6364410`, `0x6364420`, `0x63be540`,
  `0x63bf5b6`, `0x63ec4c0`, `0x63ed8b0`, `0x63eec80`, `0x63ef8e0`).
  The #314, #315, #316, #318, and #319 windows, and the #313 and
  #298 windows, are NOT called from this FDE.
- Bsr (5): at `0x635ee29`, `0x635eeb3`, `0x635f074`, `0x635f0c4`,
  `0x635f195` — all power-of-two roundings in size-class sub-blocks
  (each `bsr` + clamp + `sub $0x3` + `shl`).
- Exit: `eax` = `r15` at the single `ret` (`0x635e7eb`; epilogue
  canary check `mov 0x98(%rsp),%rax` at `0x635e7c0`,
  `sub %fs:0x28,%rax` at `0x635e7c8`, `jne 0x635f29a` ->
  `call __stack_chk_fail`; `add $0xa8,%rsp`,
  `mov %r15,%rax` at `0x635e7de`, pops, `ret`). No instruction
  writes `rax` between that `mov` and the `ret`, so the exit value
  is the element count `r15` — the fourth distinct exit register
  in the frontier. All 131 jumps target inside the window.

## Census (from the objdump exhibit, never copied from a prior packet)

- Raw `0xe8` census (byte scan for `e8` with rel32 target `0x63d9700`,
  grouped by enclosing `.eh_frame` FDE, own parse of 135,313 FDEs):
  total 168, 53 FDEs, tiers 1x18, 2x14, 3x1, 4x11, 5x1, 6x2, 7x1, 8x1,
  10x3, 13x1. This FDE holds 1 raw site, matching its 1 objdump site.
- Raw `0xe8` census for `0x63d9880` (bin_table_init): total 108, 42
  FDEs, tiers 1x17, 2x12, 4x8, 5x1, 6x2, 8x1, 10x1. This FDE holds 0
  raw sites.
- Raw `0xe8` census for `0x634ebb0` (second miss handler): total 64
  sites, 28 FDEs. This FDE holds 3 raw sites, matching its 3
  objdump sites. The next candidate `0x63c9650` holds 0 raw
  second-handler sites.
- `.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278
  entries, counted separately.
- `.bss` is `0x64ffe40..0x6728924` (NOBITS); all twelve referenced
  addresses (`0x65096a0`, `0x65096c0`, `0x6511a00`, `0x6511730`,
  `0x6511738`, `0x6711b40`, `0x6713606`, `0x67277c0`, `0x6727a00`,
  `0x6728140`, `0x6728840`, `0x6728850`) lie inside it.
  `.data.rel.ro` holds `0x64da4b0`; `.data` holds `0x64ffb80`.

## Correction to #319's pointer (proven by targeted objdump census)

#319's survey pointer for this window listed **4149 bytes, 898
strict, 38 calls, 1 lu-miss site at `0x635f30b`, 0 bin_table_init
sites, 3 second-handler sites, 1 ret at `0x635e7eb`, bsr 5** —
verified correct, along with every other figure. No correction.

## Frontier status

This packet is the seventh of the lu-miss-caller frontier (callers of
`0x63d9700` that do not call `bin_table_init`): 53 FDEs, 168 sites,
16 survivors. This window is a SHARED survivor (in the lu-miss
survivor list and in the second-handler survivor list), so claiming
it consumes one slot of the combined 25-FDE miss-handler pool
(lu-miss 16 ∪ second-handler 18, 9 shared).

## Disjointness

Range-only collector over the merged tree plus all prior `hl-wt-calls*`
worktree records (exhibits/windows only, all range-bearing forms,
decimal-integer start/end accepted, plain `int(x, 16)` for hex strings).
The window `0x635e2e0..0x635f315` overlaps no prior range (verifier:
74,019 priors scanned, 0 skipped, disjointness NONE), including packet #319's window `0x635c6d0..0x635de25`,
packet #318's window `0x635a7a0..0x635c6c7`, packet #317's window
`0x63577f0..0x635a786`, packet #316's window `0x6355900..0x63577e2`,
packet #315's window `0x6353a70..0x635582b`, packet #314's window
`0x63495b0..0x6349775`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`. The next candidate `0x63c9650..0x63c9c80` is
likewise disjoint from all priors and from this window (verifier).

## Not covered

- The bin_table_init body `0x63d9880..0x63d9a64` (#262), the lu-miss
  handler `0x63d9700..0x63d987b` (#215), the second miss handler
  `0x634ebb0..0x634eccd` (called three times from this FDE), the
  lock-wait helper `0x63bf680..0x63bf7ee` (#251), the extract helper
  FDE `0x63be540..0x63be54d`, the context helper FDE
  `0x63ef8e0..0x63efba2`, and the PLT stubs are cited, not claimed.
- The dispatcher callees' bodies are cited, not claimed — including
  the #317 window (called once) and the #314/#315/#316/#318/#319
  windows (NOT called from this FDE).
- The `.bss` objects are referenced by address only; their runtime
  contents are not established.
- The entry inputs' caller-side meaning, the walk key's caller-side
  meaning beyond its array-element origin, and the dispatcher
  callees' semantics beyond their call sites are not established.
  The exit value's meaning beyond the element count `r15` is not
  established.

## Verification

- Static verifier
  `tools/node115_lu_miss_caller_1site_arraywalk.py`:
  exit 0 (290 checks, 0 failures).
- Own unit tests
  `tests/test_node115_lu_miss_caller_1site_arraywalk.py`
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

Packet #321 decodes `0x63c9650..0x63c9c80` (1584 bytes, 363 strict,
12 calls, 2 lu-miss sites at `0x63c9c29` and `0x63c9c76`, 0
bin_table_init sites, 0 second-handler sites, 1 ret at `0x63c9868`,
bsr 0 — the next surviving lu-miss caller after this packet, verified
by targeted objdump census against all prior exhibits; it is a
lu-miss-ONLY survivor, unlike this packet).
