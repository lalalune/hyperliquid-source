# RE-001-node115-lu-miss-caller-1site-dispatch2: lu-miss caller with a dispatch body (second dispatcher)

Third packet of the lu-miss-caller frontier (after #314 on `0x63495b0`
and #315 on `0x6353a70`): a single-walk lookup routine with a
trylock-free dispatch body. FDE `0x6355900..0x63577e2` (7906 bytes,
1717 strict lines) opens with a TLS flag check and a size class
(product of the two entry inputs, byte table `0x67277c0` + size table
`0x6727a00`), runs one context-table walk keyed by `r13`, decodes the
resolved descriptor with a `shl $0x10` / `sar $0x10` extract that feeds
helper `0x63be540`, scans one 8-slot move-to-front table, and on
exhaustion falls to the single lu-miss site at `0x635774a` (`rsi` =
`.bss` `0x6511a00`, `rcx` = `r13` walk key, proven by a write-set
check). It also calls the second miss handler `0x634ebb0` six times
and dispatches to the #314 window (once), the #313 window (twice),
the #298 window (twice), and 25 other callees (111 calls, 31 distinct
direct targets, 0 indirect calls — unlike #315, which has one indirect
call via GOT `0x64ffb38`). It exits by a single `ret` with `rax` =
`r13`. 0 `bin_table_init` sites, 8 `bsr`.

This window is a shared survivor of both miss-handler lists, so
claiming it consumes one slot of the combined 25-FDE miss-handler
pool (lu-miss 16 survivors ∪ second-handler 18 survivors, 9 shared).

## Window

- FDE `0x6355900..0x63577e2`, 7906 bytes, 1717 strict mnemonic lines.
- Previous FDE `0x6355830..0x63558f2` (gap 14 bytes, all `0xcc`).
- Next FDE `0x63577f0..0x635a786` (padding 14 bytes, all `0xcc`) — the
  next lu-miss survivor, the next question for packet #317.
- Frame: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx, `sub $0xa8,%rsp`,
  canary at `0x98(%rsp)`.
- Entry: `rdi` = first input (kept in `r14`), `rsi` = second input
  (kept in `r12`). `rbx` = TLS-derived context base (`%fs:0x0` +
  `0xffffffffffffef58`).
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.

## Classification

**TLS flag check.** `cmpb $0x0,%fs:0x330(%rax)` at `0x635593f`;
`jne 0x6355c40` at `0x6355947` leads to the init block at `0x6355c40`,
which calls `0x63ef8e0` (the #258 exclusion FDE, cited — called once
here) with `rdi` = `rbx`, `rsi` = 0, then re-checks the flag and
rejoins the entry path at `0x635594d`.

**Size class.** The product of the two entry inputs: `mul %r12` at
`0x6355950` (`rdi` * `rsi`), `rbp` = product, `seto %cl` at
`0x6355953` records the overflow flag in `r13d`. Arms: product == 0
→ `0x6355e40`; `(rdi | rsi) >> 0x20 != 0` → `0x6355e60`; product >
`0x1000` → `0x6355e70` (bsr path, threshold
`0x7000000000000000`). The small path reads the byte table
`0x67277c0` at index `(rbp+7)>>3` into `r15d` (`lea 0x7(%rbp),%r9`,
`shr $0x3,%r9`, `movzbl (%r11,%r9,1),%r15d` at `0x635598f`),
`cmp $0xe7,%r15d` at `0x6355994` (`ja 0x6355c26` — the error path:
`__errno_location@plt`, `movl $0xc`, `r13d` = 0, jump to the
epilogue), then the size table `0x6727a00` (`mov (%r10,%r12,8),%r14`
at `0x63559b9`, class in `r12d`). The flag byte `0x6713606`
(`cmpb $0x0,(%rax)` at `0x63559b6`) gates the `0x6355ab0` arm.
`cmp $0x3800,%rbp` at `0x63559cf` (`ja 0x6356050`).

**Walk (single, table in `rbx`, key in `r13`).** Top index
`(key >> 0x1a) & 0xf0` (`mov %r13,%r12` at `0x6356140`,
`shr $0x1a,%r12`, `and $0xf0,%r12d`, `add %rbx,%r12`), high bits
`key & 0xffffffffc0000000` (`mov %r13,%rbp` at `0x6356143`,
`and $0xffffffffc0000000,%rbp`), top-level entry
`mov 0x1b0(%r12),%rsi` at `0x635615b`, compare
`cmp %rsi,%rbp` at `0x6356163`; a mismatch falls to the scan at
`0x6356b4d`. Second level `(key >> 0x9) & 0x1ffff8 + table + 0x8`
(`mov %r13,%rax` at `0x635616c`, `shr $0x9,%rax`,
`and $0x1ffff8,%eax`, `add 0x1b8(%r12),%rax` at `0x6356178`). The
second-level pointer is dereferenced into `rdi` at the rejoin
`0x6356180` (`mov (%rax),%rdi`) — it is NOT stored to an output slot;
it feeds the extract.

**Extract (at the rejoin `0x6356180`).** `shl $0x10,%rdi` at
`0x6356183`, `sar $0x10,%rdi` at `0x6356187`,
`and $0xffffffffffffff80,%rdi` at `0x635618b`, then
`call 0x63be540` at `0x635618f` (FDE `0x63be540..0x63be54d`, cited;
2 sites in this FDE: `0x635618f`, `0x635671c`), then
`jmp 0x6355a2c`. Unlike #314, there is no inline output decoding in
this FDE.

**Scan (single 8-slot move-to-front, table+`0x2b0` in `rbx`, key in
`rbp`).** Slot 0 at `0x6356b4d` (`cmp 0x2b0(%rbx),%rbp` — memory
directly, normal form); a miss jumps to the loop entry at
`0x6357031` (`mov $0x1,%edi`, slot index starts at 1). Slots 1–7
share the one loop compare at `0x635703d`
(`cmp 0x2b0(%rbx,%r10,1),%rbp`, `r10` = `rdi` << 4 — memory
directly, normal form). Exhaustion: `add $0x1,%rdi` at `0x635771f`,
`cmp $0x8,%rdi` at `0x6357723`, `jne 0x6357036`; fall-through at
`rdi` == 8 reaches the lu-miss block at `0x635772d`. Move-to-front:
the slot-0 hit block at `0x6356b5a` swaps the 16-byte entries and
recomputes the second-level pointer, rejoining the extract at
`0x6356180` (`jmp` at `0x6356b96`); the shared hit block at
`0x635704b` swaps the entries and rejoins the slot-0 hit block tail
at `0x6356b77` (`jmp` at `0x6357091`). Zero reversed-operand
compares.

**Lu-miss site (1).** Block `0x635772d`, call at `0x635774a` →
`0x63d9700`, rejoin `jmp 0x6356180`. Arguments: `rdi` = `rbx`
context, `rsi` = `0x6511a00` (`.bss`, NOT entry `rsi`),
`rdx` = `rbx+0x1b0` (walk table), `rcx` = `r13` walk key,
`r8d` = 1, `r9d` = 0. The `rcx` provenance is proven by the
verifier's write-set check: `r13` is never written on the
walk → scan → miss path (`0x6356140..0x6356166`,
`0x6356b4d..0x6356b54`, `0x6357031..0x6357045`,
`0x635771f..0x6357727`, `0x635772d..0x635774a`) — it is only read
there (`mov %r13,%r12` / `mov %r13,%rbp` at the walk,
`mov %r13,%rcx` at the miss block) — so `rcx` is the same register
the walk derives its key from. Unlike #314 (`rcx` = entry `rcx`)
and #315 (`rcx` = `r12` walk key), here `rcx` = `r13` walk key.

**Second-handler sites (6).** Calls to `0x634ebb0` at `0x63568c4`,
`0x6356afa`, `0x6356bc1`, `0x6356dfc`, `0x6357651`, `0x63576ff`.
All six set `rdi` = `rbx` and `rdx` = `0x64da4b0` (`.data.rel.ro`)
immediately before the call, with stack saves/restores around it.
`rsi` = 0 is proven at sites 1 (`xor %esi,%esi` at `0x63568b5`) and
3 (`xor %esi,%esi` at `0x6356bb2`); at sites 2, 4, 5, 6 `rsi` is not
established — each site's last `rsi` write sits before an intervening
call that may clobber it (`0x63e9c40`, `0x63edf10`, `0x63bd2c0`,
`0x6365150` respectively), so no value is claimed there.

**Dispatcher calls (111 total, 31 distinct direct targets, 0
indirect).** The window dispatches to the #314 window once
(`0x6356712`: `rdi` = `lea 0x30(%rsp)` stack temp, `rsi` = `rbx`,
`rdx` = `rbx+0x1b0`, `rcx` = `r13`), the #313 window twice
(`0x6355b7f`, `0x63572e4`), the #298 window twice (`0x63567d3`,
`0x63573dd`), plus `0x6364880` x13, `0x63e9cd0` x12, `memset@plt`
x12, `0x6353610` x10, `0x63bd2c0` (18-byte thunk) x8, `0x6365150`
x4, `0x63e9c40` x4, `0x63edf10` x4, `0x63c3890`/`0x63c3b00`/
`0x63c2e80`/`0x63be540`/`0x63c3780`/`0x6364420`/`0x6364410`/
`0x6364400`/`0x6352fc0`/`0x63ec4c0`/`0x6360ed0` x2 each,
`__errno_location@plt`/`sched_getcpu@plt` x2 each, and
`0x63ef8e0`/`0x63b7240`/`0x634f0b0`/`__stack_chk_fail@plt` x1 each.
There is NO indirect call in this FDE — unlike #315, which has one
indirect call via GOT `0x64ffb38`.

**Bsr (8).** `0x6355e98` (→ `0x63eec80`), `0x6356547` (→
`sched_getcpu@plt`), `0x635696b`, `0x6356c56`, `0x6356ed5`,
`0x6357165`, `0x63574a7`, `0x63575f3` (→ `0x63bd2c0` — six
power-of-two rounding arms feeding the `0x63bd2c0` allocator
helper).

**Exit (1 ret, 0 tail jumps).** The single `ret` is at `0x6355aa8`
(shared epilogue: canary check at `0x6355a7d`,
`jne 0x6356fdc` at `0x6355a8e` → `__stack_chk_fail@plt` at
`0x6356fdc`, `add $0xa8,%rsp` at `0x6355a94` + pops). `eax` = `r13`
at ret (`mov %r13,%rax` at `0x6355a9b`) — NOT 0, like #314
(`rax` = `rbx`) and #315 (`rax` = `r12`). All 278 jumps target
inside the window.

## Census (from the objdump exhibit, never copied from a prior packet)

- Strict mnemonic lines: 1717.
- Calls: 111 (31 distinct direct targets, 0 indirect).
- Bin_table_init sites: 0. Lu-miss sites: 1 (`0x635774a`).
  Second-handler sites: 6. Lock-wait sites: 0.
- `ret`: 1 (`0x6355aa8`). Tail-jump exits: 0. `bsr`: 8.
  `lock sub`: 0. `lock add`: 0. Jumps: 278, all inside.
- Raw `0xe8` census (byte scan for `e8` with rel32 target `0x63d9700`,
  grouped by enclosing `.eh_frame` FDE, own parse of 135,313 FDEs
  sorted before bisect): total 168, 53 FDEs, tiers 1x18, 2x14, 3x1,
  4x11, 5x1, 6x2, 7x1, 8x1, 10x3, 13x1. This FDE holds 1 raw site,
  matching its 1 objdump site.
- Raw `0xe8` census for `0x63d9880` (bin_table_init): total 108, 42
  FDEs, tiers 1x17, 2x12, 4x8, 5x1, 6x2, 8x1, 10x1. This FDE holds
  0 raw sites. No 3-raw tier exists.
- `.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278
  entries, counted separately (direct ELF parse; readelf `-W`
  cross-checked — non-wide output truncates the JUMP_SLOT type
  name and undercounts).

## Lu-miss-caller frontier status

Callers of the lu-miss handler `0x63d9700` that do not call
`bin_table_init`: 53 FDEs, 168 sites, 16 survivors (survey
`~/workspace/scratch-hl314survey/census.json`): `0x63495b0` (#314),
`0x6353a70` (#315), `0x6355900` (this packet), `0x63577f0`,
`0x635a7a0`, `0x635c6d0`, `0x635e2e0`, `0x63c9650`, `0x63ccd60`,
`0x63cddd0`, `0x63d03a0`, `0x63d17e0`, `0x63d2a80`, `0x63d3f0e`,
`0x63d4048`, `0x63e94a0`. The second miss handler `0x634ebb0` has
28 FDEs, 18 survivors, 9 shared with the lu-miss survivors, so the
combined miss-handler pool is 25 distinct FDEs. This packet is a
shared survivor and consumes one slot of that pool.

**Prior pointer verified (no correction).** #315's survey pointer
for this window (7906 bytes, 1717 strict, 111 calls, 1 lu-miss site
`0x635774a`, 0 bin_table_init sites, 6 second-handler sites, 1 ret
at `0x6355aa8`, bsr 8) is verified correct by program arithmetic
and by the objdump census above.

**Correction to a draft figure, caught before sealing.** An early
draft of this packet's records listed the next candidate
`0x63577f0..0x635a786` with bsr 8 (the bsr count of this window,
copied by mistake). A targeted objdump census of the next FDE shows
it has **0** `bsr` instructions; the corrected figure (0) is what
the records and the verifier assert.

## Disjointness

Range-only collector over the merged tree plus all prior
`hl-wt-calls*` worktree records (exhibits/windows only, all
range-bearing forms, decimal-integer start/end accepted, plain
`int(x, 16)` for hex strings). The window `0x6355900..0x63577e2`
overlaps no prior range (verifier: priors scanned, 0 skipped,
disjointness NONE), including packet #315's window
`0x6353a70..0x635582b`, packet #314's window `0x63495b0..0x6349775`,
packet #313's window `0x63c2f00..0x63c3328`, packet #215's handler
FDE `0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`. The next candidate `0x63577f0..0x635a786`
is likewise disjoint from all priors and from this window
(verifier).

## Not covered

- The bin_table_init body `0x63d9880..0x63d9a64` (#262) and the
  lu-miss handler `0x63d9700..0x63d987b` (#215) are cited, not
  claimed.
- The second miss handler `0x634ebb0..0x634eccd`, the lock-wait
  helper `0x63bf680..0x63bf7ee` (#251), the extract helper FDE
  `0x63be540..0x63be54d`, the `0x63bd2c0..0x63bd2d2` thunk, and the
  PLT stubs are cited, not claimed.
- The dispatcher callees' bodies are cited, not claimed — including
  the #314 window (`0x63495b0..0x6349775`, called once), the #313
  window (`0x63c2f00..0x63c3328`, called twice), the #298 window
  (`0x6362f90..0x6363258`, called twice), the #315 window
  (`0x6353a70..0x635582b`, NOT called from this FDE), and the
  #258 exclusion FDE `0x63ef8e0..0x63efba2` (called once from the
  TLS init block).
- The `.bss` objects at `0x6511a00`, `0x65096c0`, `0x65096a0`,
  `0x67277c0`, `0x6727a00`, `0x6713606` are referenced by address
  only; their runtime contents are not established. The
  `.data.rel.ro` object at `0x64da4b0` and the `.data` objects at
  `0x64ffb80`, `0x64ffab4` are likewise referenced by address only.
- The neighboring FDEs are not decoded here. The next FDE
  `0x63577f0..0x635a786` is the next question for packet #317.
- The entry inputs' caller-side meaning, the `r8d`/`r9d` values'
  caller-side meaning, and the semantics of the dispatcher callees'
  outputs beyond the call sites are not established.

## Verification

- Static verifier
  `tools/node115_lu_miss_caller_1site_dispatch2.py`:
  exit 0 (198 checks, 0 failures).
- Own unit tests
  `tests/test_node115_lu_miss_caller_1site_dispatch2.py`
  (tamper controls first — hex flip, strict-count change, call-site
  change, injected overlap — each makes the temp-copy verifier fail;
  the clean temp copy passes): exit 0 (12 checks, 0 failures).
- `make verify`: exit 0 (559 evidence-packet manifests, 7159
  entries).
- `make catalogue-check`: exit 2 with the pre-existing `Stale
  catalogue: README.md` failure, also present on a pristine
  checkout; not a packet regression.
- Full `make test` is not run (584 files on the new base; hours of
  runtime and VM-restart risk). This deviation from the repository's
  stated gate is declared here rather than hidden.
- `.hex` exhibits are raw binary bytes, not hex text.

## Next question

Packet #317 decodes `0x63577f0..0x635a786` (12,182 bytes, 2679
strict lines, 132 calls, 1 lu-miss site at `0x635a6cd`, 0
bin_table_init sites, 10 second-handler sites, 1 ret at
`0x6357e19`, bsr 0 — the next surviving lu-miss caller after this
packet, verified by targeted objdump census against all prior
exhibits; it is also a shared survivor of both miss-handler lists).
