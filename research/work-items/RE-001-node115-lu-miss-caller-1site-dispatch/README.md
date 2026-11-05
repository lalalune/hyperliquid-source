# RE-001: lu miss caller 1-site dispatch

Second packet of the lu-miss-caller frontier (after #314 on
`0x63495b0`, PR #3255). The window is a large dispatcher-like routine
with one lu-miss site and no bin_table_init site: FDE
`0x6353a70..0x635582b` (7611 bytes, 1691 strict lines, 105 calls,
1 ret, bsr 8). It opens with a TLS flag check and a size-class
computation (byte table `0x67277c0` + size table `0x6727a00`), runs a
single context-table walk that resolves a second-level pointer, an
`shl $0x10` / `sar $0x10` extract that feeds helper `0x63be540`,
and a single 8-slot move-to-front scan whose exhaustion falls to the
one lu-miss site. It also calls the second miss handler `0x634ebb0`
six times, #314's window once, #313's window twice, and #298's
window twice. This window is a SHARED survivor of both miss-handler
lists (lu-miss 16 and second-handler 18), so claiming it consumes one
slot of the combined 25-FDE miss-handler pool.

## Window

- FDE `0x6353a70..0x635582b`, 7611 bytes, 1691 strict mnemonic lines.
- Previous FDE `0x6353a20..0x6353a61` (gap 15 bytes, all `0xcc`).
- Next FDE `0x6355830..0x63558f2` (padding 5 bytes, all `0xcc`).
- Frame: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx, `sub $0x98,%rsp`,
  canary at `0x88(%rsp)`.
- Entry: `rdi` = size input (kept in `rbp`; compared against `0x1000`
  and `0x3800`; byte-table index `(rbp+7)>>3`); `rbx` =
  `%fs:0x0 + 0xffffffffffffef58` (TLS-derived context base). Entry
  `rsi`/`rdx`/`rcx`/`r9` are not read before being overwritten on the
  entry path.
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.
- No bin_table_init site in this FDE (0 raw `0xe8` sites with rel32
  target `0x63d9880`).

## Classification

**TLS flag check.** `mov %fs:0x0,%rbx` at `0x6353a88`,
`mov $0xffffffffffffef58,%rax` at `0x6353aa2`,
`add %rax,%rbx` at `0x6353aa9`,
`cmpb $0x0,%fs:0x330(%rax)` at `0x6353aac`,
`jne 0x6353d50` at `0x6353ab4`.

**Size class at entry.** `cmp $0x1000,%rbp` at `0x6353aba`
(`ja 0x6353f20`); byte table `0x67277c0` read at index `(rbp+7)>>3`
(`lea 0x7(%rbp),%r8` at `0x6353ace`, `shr $0x3,%r8`,
`movzbl (%r9,%r8,1),%r14d` at `0x6353ad6` with `r9` from
`lea 0x3d3cf2(%rip),%r9`); `cmp $0xe7,%r14d` at `0x6353adb`
(`ja 0x6353d3c`); size table `0x6727a00`
(`lea 0x3d3f0a(%rip),%r11` at `0x6353aef`,
`mov (%r11,%r8,8),%r13` at `0x6353b00`); flag `0x6713606`
(`lea 0x3bfb17(%rip),%rax` at `0x6353ae8`,
`cmpb $0x0,(%rax)` at `0x6353afd`, `jne 0x6353be0`).
`cmp $0x3800,%rbp` at `0x6353b11` (`ja 0x6354020`).

**Walk (single, table in `rbx` + top index).** Key `r12` loaded at
`0x6354094` (`mov (%rdx),%r12`, where `rdx` comes from
`0x360(%rsi)` at `0x635408d` and `rsi` from the size-class block).
Top index `(key >> 0x1a) & 0xf0` (`shr $0x1a,%r15` at `0x63540c6`,
`and $0xf0,%r15d` at `0x63540d1`, `add %rbx,%r15` at `0x63540d8`),
high bits `key & 0xffffffffc0000000`
(`mov %r12,%r10` at `0x63540c3`, `and` at `0x63540ca`), top-level
compare `cmp %rbp,%r10` at `0x63540e2`; a mismatch falls to the scan
at `0x6354c80`. Second level `(key >> 0x9) & 0x1ffff8 + table + 0x8`
(`shr $0x9,%rax` at `0x63540ee`, `and $0x1ffff8,%eax` at `0x63540f2`,
`add 0x1b8(%r15),%rax` at `0x63540f7`). The second-level pointer is
loaded into `rdi` at `0x63540fe` — it is NOT stored to an output slot;
it feeds the extract.

**Extract.** `shl $0x10,%rdi` at `0x6354101`,
`sar $0x10,%rdi` at `0x6354105`,
`and $0xffffffffffffff80,%rdi` at `0x6354109`, then
`call 0x63be540` at `0x635410d`. Unlike #314, there is no inline
output decoding in this FDE — the extract feeds helper `0x63be540`
directly (called twice in this FDE: `0x635410d`, `0x635468c`).

**Scan (single 8-slot move-to-front, table+`0x2b0` in `rbx`, key in
`r10` = key high bits).** Slot 0 at `0x6354c80`
(`cmp 0x2b0(%rbx),%r10`); a hit swaps the top entry and rejoins the
second-level deref at `0x6354ca9` (`jmp 0x63540fe` at `0x6354cc6`).
Slots 1–7 share one loop compare at `0x6355275`
(`cmp 0x2b0(%rbx,%rsi,1),%r10`, `rsi` = `r11 << 4`), entered at
`0x6355268` (`mov $0x1,%r11d` — the slot index starts at 1; the only
jump to `0x6355268` is the `jne` at `0x6354c87`). A hit runs the
move-to-front swap block at `0x6355283..0x63552c9` (16-byte entries at
`0x2b0`/`0x2b8`) and rejoins `jmp 0x6354ca9` at `0x63552c9`.
Exhaustion at `0x63557c0` (`add $0x1,%r11`, `cmp $0x8,%r11`,
`jne 0x635526e`): when `r11` reaches 8 the fall-through reaches the
lu-miss block at `0x63557ce`. Zero reversed-operand compares (both
compares are memory-first).

**Lu-miss site (1).** Block `0x63557ce`, call at `0x63557eb`
(`e8 10 3f 08 00` -> `0x63d9700`), rejoin `jmp 0x63540fe` at
`0x63557f0` (the second-level deref). Arguments: `rdi` = `rbx`
context (`mov %rbx,%rdi` at `0x63557db`), `rsi` = `0x6511a00`
(`.bss`, `lea` at `0x63557ce`), `rdx` = `lea 0x1b0(%rbx)` at
`0x63557de` (walk table), `rcx` = `r12` walk key
(`mov %r12,%rcx` at `0x63557d8`), `r8d` = 1 (`mov $0x1,%r8d` at
`0x63557e5`), `r9d` = 0 (`xor %r9d,%r9d` at `0x63557d5`). The
`rcx` provenance is proven by the verifier's write-set check: the
only `r12` write on the walk-entry -> scan -> miss path is the key
load at `0x6354094`.

**Second miss handler sites (6).** Calls at `0x6354912`,
`0x6354b44`, `0x6354cf9`, `0x6354e1d`, `0x6355730`, `0x635578d`.
All six: `rdi` = `rbx` context, `rdx` = `0x64da4b0`
(`.data.rel.ro`, `lea` immediately before the call). `rsi` = 0 at
`0x6354912` and `0x6354b44` (`xor %esi,%esi` immediately before);
at the other four sites `rsi` is carried from the incoming dispatch
path (`mov %r12,%rsi` at `0x6354ccb` / `0x63556ed` on those paths).
Caller-saved registers are saved to the stack before and restored
after each of the six calls.

**Dispatcher callees.** #314's window `0x63495b0` once at
`0x6354682` (`rdi` = `lea 0x20(%rsp)` stack temp, `rsi` = `rbx`,
`rdx` = `lea 0x1b0(%rbx)`, `rcx` = `r12`, `mov %r10b,(%rsp)`; after
return `mov 0x20(%rsp),%rdi` then `call 0x63be540` at `0x635468c`).
#313's window `0x63c2f00` twice at `0x6353caa` and `0x6355415`
(`rdi` = `rbx`, `rsi` = `r12`, `rdx` = `rbp`, `rcx` = `r13`,
`r8` = `r15` at the first site). #298's window `0x6362f90` twice.
`0x6364880` 13 times, `0x63e9cd0` 12 times, `0x63bd2c0` 8 times
(18-byte thunk: `movzbl %cl,%r8d`, `mov $0x40,%ecx`,
`jmp 0x63bcd20`), `0x6353610` 5 times, `0x63537f0` 5 times,
`0x6365150` / `0x63e9c40` / `0x63edf10` 4 times each, and twelve
further callees twice each. PLT: `memset` 5, `__errno_location` 2,
`sched_getcpu` 2, `__stack_chk_fail` 1. One indirect call at
`0x635481f` (`call *0x1ab313(%rip)`, GOT slot `0x64ffb38` in
`.data`, `R_X86_64_RELATIVE` — runtime-filled, value not in file).

**Bsr (8).** At `0x6353f49`, `0x63543a3`, `0x635496f`, `0x6354baf`,
`0x6354eee`, `0x6355102`, `0x63551cc`, `0x6355662` — all in dispatch
arms computing slot/class indices (four immediately preceded by
`sub $0x1`).

**Exit (1 ret, 0 tail jumps).** The single `ret` is at `0x6353bdb`
(shared epilogue at `0x6353bb0`: canary check at `0x6353bb8`,
`jne 0x6355043` at `0x6353bc1`, `add $0x98,%rsp` at `0x6353bc7`,
`mov %r12,%rax` at `0x6353bce` + pops). Canary failure goes to
`0x6355043`, which calls `__stack_chk_fail` (`0x63f0d70`). All 282
jump instructions target inside the window. `eax` = `r12` at ret
(like #314, where `rax` = `rbx` — NOT 0, unlike the bin_table_init
caller chain where `eax` = 0 at ret).

## Census (from the objdump exhibit, never copied from a prior packet)

- Strict mnemonic lines: 1691.
- Calls: 105 (33 distinct targets: 32 direct + 1 indirect).
- Bin_table_init sites: 0. Lu-miss sites: 1 (`0x63557eb`).
  Second-handler sites: 6. Lock-wait sites: 0.
- `ret`: 1 (`0x6353bdb`). Tail-jump exits: 0. `bsr`: 8.
  `lock sub`: 0. `lock add`: 0. Jumps: 282 (0 outside the window).
- Raw `0xe8` census (byte scan for `e8` with rel32 target `0x63d9700`,
  grouped by enclosing `.eh_frame` FDE, own parse of 135,313 FDEs):
  total 168, 53 FDEs, tiers 1x18, 2x14, 3x1, 4x11, 5x1, 6x2, 7x1, 8x1,
  10x3, 13x1. This FDE holds 1 raw site, matching its 1 objdump site.
- Raw `0xe8` census for `0x63d9880` (same method): total 108, 42 FDEs,
  tiers 1x17, 2x12, 4x8, 5x1, 6x2, 8x1, 10x1. This FDE holds 0 raw
  sites.
- `.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278
  entries, counted separately (direct ELF parse; readelf `-W`
  cross-checked).

## Lu-miss-caller frontier status

Packet #314 surveyed the frontier: 53 FDEs hold 168 lu-miss sites;
16 survive as non-bin_table_init callers
(`0x63495b0`, `0x6353a70`, `0x6355900`, `0x63577f0`, `0x635a7a0`,
`0x635c6d0`, `0x635e2e0`, `0x63c9650`, `0x63ccd60`, `0x63cddd0`,
`0x63d03a0`, `0x63d17e0`, `0x63d2a80`, `0x63d3f0e`, `0x63d4048`,
`0x63e94a0`). The second miss handler `0x634ebb0` has 28 FDEs and
18 survivors; 9 FDEs are shared between the two lists, so the
combined miss-handler pool is 25 distinct FDEs. This packet is the
second of the 16 lu-miss survivors and a SHARED survivor — claiming
it consumes one slot of the combined 25-FDE pool.

## Disjointness

Range-only collector over the merged tree plus all prior
`hl-wt-calls*` worktree records (exhibits/windows only, all
range-bearing forms, decimal-integer start/end accepted, plain
`int(x, 16)` for hex strings). The window `0x6353a70..0x635582b`
overlaps no prior range (verifier: 69,804 priors scanned, 0 skipped,
disjointness NONE), including packet #314's window
`0x63495b0..0x6349775`, packet #313's window `0x63c2f00..0x63c3328`,
packet #215's handler FDE `0x63d9700..0x63d987b`, and packet #262's
bin_table_init window `0x63d9880..0x63d9a64`.

## Not covered

- The bin_table_init body `0x63d9880..0x63d9a64` (#262) and the
  lu-miss handler `0x63d9700..0x63d987b` (#215) are cited, not
  claimed.
- The second miss handler `0x634ebb0..0x634eccd`, the lock-wait
  helper `0x63bf680..0x63bf7ee` (#251), the extract helper FDE
  `0x63be540..0x63be54d`, the 18-byte thunk FDE
  `0x63bd2c0..0x63bd2d2`, and the PLT stubs are cited, not claimed.
- #314's window `0x63495b0..0x6349775`, #313's window
  `0x63c2f00..0x63c3328`, #298's window `0x6362f90..0x6363258`, and
  every other dispatcher callee are cited, not claimed.
- The `.data.rel.ro` object at `0x64da4b0` and the `.data` objects at
  `0x64ffb80` / `0x64ffb38` are referenced by address only; the
  indirect call's runtime target is not established. The `.bss`
  objects at `0x6511a00`, `0x6511730`, `0x65096c0`, `0x67277c0`,
  `0x6727a00`, `0x6713606` are referenced by address only; their
  runtime contents are not established.
- The neighboring FDEs are not decoded here. The next FDE
  `0x6355900..0x63577e2` is the next question for packet #316.
- The entry `rdi` size input's caller-side meaning, the dispatch
  arms' selection semantics, and the extract helper's outputs beyond
  the call site are not established.

## Verification

- Static verifier
  `tools/node115_lu_miss_caller_1site_dispatch.py`:
  exit 0 (188 checks, 0 failures).
- Own unit tests
  `tests/test_node115_lu_miss_caller_1site_dispatch.py`
  (tamper controls first — hex flip, strict-count change, call-site
  change, injected overlap — each makes the temp-copy verifier fail;
  the clean temp copy passes): exit 0 (12 checks, 0 failures).
- `make verify`: exit 0 (559 evidence-packet manifests, 7159 entries).
- `make catalogue-check`: exit 2 with the pre-existing `Stale
  catalogue: README.md` failure, also present on a pristine
  checkout; not a packet regression.
- Full `make test` is not run (584 files on the new base; hours of
  runtime and VM-restart risk). This deviation from the repository's
  stated gate is declared here rather than hidden.
- `.hex` exhibits are raw binary bytes, not hex text.

## Next question

Packet #316 decodes `0x6355900..0x63577e2` (7906 bytes, 1717 strict
lines, 111 calls, 1 lu-miss site at `0x635774a`, 0 bin_table_init
sites, 6 second-handler sites, 1 ret at `0x6355aa8`, bsr 8 — the
next surviving lu-miss caller after this packet, verified by targeted
objdump census against all prior exhibits; it is also a shared
survivor of both miss-handler lists).
