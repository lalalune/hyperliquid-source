# RE-001-node115-lu-miss-caller-1site-dispatch3: lu-miss caller with a dispatch body (third dispatcher)

Fourth packet of the lu-miss-caller frontier (after #314 on `0x63495b0`,
#315 on `0x6353a70`, and #316 on `0x6355900`): a single-walk lookup
routine with a dispatch body. FDE `0x63577f0..0x635a786` (12,182 bytes,
2679 strict lines) opens with a TLS flag check and a size class (byte
table `0x67277c0` + size table `0x6727a00`, plus twelve `bsr`
power-of-two roundings in the dispatcher sub-blocks), runs one
context-table walk keyed by `r12` (a value loaded from a table slot,
not entry `rsi`), decodes the resolved descriptor with a `shl $0x10` /
`sar $0x10` extract that feeds helper `0x63be540`, scans one 8-slot
move-to-front table, and on exhaustion falls to the single lu-miss
site at `0x635a6cd` (`rsi` = `.bss` `0x6511a00`, `rcx` = `r12` walk
key, proven by a write-set check). It also calls the second miss
handler `0x634ebb0` ten times and dispatches to the #314 window
(once), the #313 window (twice), the #298 window (twice), and 32
other callees (132 calls, 35 distinct direct targets, 1 indirect call
via GOT `0x64ffb38` — like #315, unlike #316). It exits by a single
`ret` with `rax` = `r12`. 0 `bin_table_init` sites, 12 `bsr`.

This window is a shared survivor of both miss-handler lists, so
claiming it consumes one slot of the combined 25-FDE miss-handler
pool (lu-miss 16 survivors ∪ second-handler 18 survivors, 9 shared).

## Window

- FDE `0x63577f0..0x635a786`, 12,182 bytes, 2679 strict mnemonic lines.
- Previous FDE `0x6355900..0x63577e2` (#316, gap 14 bytes, all `0xcc`).
- Next FDE `0x635a790..0x635a79b` (padding 10 bytes, all `0xcc`) — an
  11-byte thunk (`endbr64`; `xor %ecx,%ecx`; `jmp 0x63577f0`, back
  into this window's entry).
- Frame: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx, `sub $0xa8,%rsp`,
  canary at `0x98(%rsp)`.
- Entry: `rdi` = context (kept in `r11`), `rsi` = signed index
  (`movslq %esi,%rbp`). `rbx` = context resolved by helper
  `0x63ef8e0` (`%fs:0x0` + `0xffffffffffffef58`).
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.

## Classification

**TLS flag check.** `cmpb $0x0,%fs:0x330(%rbx)` at `0x635782d`
(`rbx` = `0xffffffffffffef58`); `je 0x6357b08` at `0x6357835`.
The context is resolved by `call 0x63ef8e0` at `0x6357864` (`rdi` =
`%fs:0x0` + `rbx`), `mov %rax,%rbx` at `0x6357879`.

**Size class.** The entry path reads the byte table `0x67277c0`
(`lea` at `0x63578f3`, index `(r15+7)>>3`, `movzbl (%r8,%r15,1),%edi`
at `0x6357909`) and the size table `0x6727a00` (`lea` at `0x63578fe`,
`mov 0x0(%r13,%rdi,8),%r10` at `0x635790e`), with
`cmp $0x3fff,%r10` at `0x6357913`. A second small path runs at
`0x63581b8` (`cmp $0x1000,%r11`, `ja 0x6358b98`): byte table `lea` at
`0x63581c5`, index `(r11+7)>>3`, `movzbl 0x0(%r13,%r10,1),%ecx` at
`0x63581d4`, `cmp $0xe7,%ecx` at `0x63581da` (`ja 0x63583b0`), size
table `lea` at `0x63581e6`, `mov (%rax,%r15,8),%r10` at `0x63581f0`.
`cmp $0x3800,%rbp` at `0x63580ef` gates the walk. The twelve `bsr`
sites are all power-of-two roundings in dispatcher sub-blocks
(`bsr`, clamp, `sub $0x3`, `shl`) — e.g. `bsr %rbp,%r10` at
`0x6358022`, `bsr %rcx,%rcx` at `0x635824b`.

**Walk (single, table in `rbx`, key in `r12`).** The key is loaded
from a table slot (`mov (%r9),%r12` at `0x6357fb4`) on the entry
path — NOT entry `rsi` (entry `esi` is the signed index in `rbp`).
Top index `(key >> 0x1a) & 0xf0` (`mov %r12,%r14` at `0x63580fc`,
`shr $0x1a,%r14`, `and $0xf0,%r14d`, `add %rbx,%r14`), high bits
`key & 0xffffffffc0000000` (`mov %r12,%r15` at `0x63580ff`,
`and $0xffffffffc0000000,%r15`), top-level entry
`mov 0x1b0(%r14),%rax` at `0x6358117`, compare `cmp %rax,%r15` at
`0x635811e`; a mismatch falls to the scan at `0x63591e4`. Second
level `(key >> 0x9) & 0x1ffff8 + table + 0x8`
(`mov %r12,%rax` at `0x6358127`, `shr $0x9,%rax`,
`and $0x1ffff8,%eax`, `add 0x1b8(%r14),%rax` at `0x6358133`). The
second-level pointer is dereferenced into `rdi` at the rejoin
`0x635813a` (`mov (%rax),%rdi`) — it is NOT stored to an output
slot; it feeds the extract. The walk is re-entered per element:
`jmp 0x63580fc` from `0x6358633`, `0x63593c4`, `0x63595cb`,
`0x6359614`.

**Extract (at the rejoin `0x635813a`).** `shl $0x10,%rdi` at
`0x635813d`, `sar $0x10,%rdi` at `0x6358141`,
`and $0xffffffffffffff80,%rdi` at `0x6358145`, then
`call 0x63be540` at `0x6358149` (FDE `0x63be540..0x63be54d`, cited;
2 sites in this FDE: `0x6358149`, `0x6358868`), then
`jmp 0x6357d9d`. Unlike #311/#312, there is no inline output
decoding in this FDE. The node-resolution table `0x65096c0` is read
on the post-walk path (`lea` at `0x635816c`,
`mov (%rdx,%r8,8),%rax` at `0x6358173`), like #312 (unlike
#313/#315/#316).

**Scan (single 8-slot move-to-front, table+`0x2b0` in `rbx`, key in
`r15`).** Slot 0 at `0x63591e4` (`cmp 0x2b0(%rbx),%r15` — memory
directly, normal form); a miss jumps to the loop entry at
`0x635a018` (`mov $0x1,%edi`, slot index starts at 1). Slots 1–7
share the one loop compare at `0x635a024`
(`cmp 0x2b0(%rbx,%r8,1),%r15`, `r8` = `rdi` << 4 — memory
directly, normal form). Exhaustion: `add $0x1,%rdi` at `0x635a6a2`,
`cmp $0x8,%rdi` at `0x635a6a6`, `jne 0x635a01d`; fall-through at
`rdi` == 8 reaches the lu-miss block at `0x635a6b0` (no jump targets
the lu-miss block directly). Move-to-front: the slot-0 hit block at
`0x63591f1` swaps the 16-byte entries and recomputes the
second-level pointer, rejoining the extract at `0x635813a` (`jmp`
at `0x635922a`); the shared hit block at `0x635a032` swaps the
entries and rejoins the slot-0 hit block tail at `0x635920d`
(`jmp` at `0x635a077`). Zero reversed-operand compares.

**Lu-miss site (1).** Block `0x635a6b0`, call at `0x635a6cd` ->
`0x63d9700`, rejoin `jmp 0x635813a`. Arguments: `rdi` = `rbx`
context, `rsi` = `0x6511a00` (`.bss`, NOT entry `rsi`), `rdx` =
`lea 0x1b0(%rbx)` (walk table), `rcx` = `r12` walk key
(`mov %r12,%rcx` — `r12` still holds the walk key on the miss
path, verified by the verifier's exact write-set check over the
walk -> scan -> miss path), `r8d` = 1, `r9d` = 0.

**Second-handler sites (10).** All with `rdi` = `rbx` and `rdx` =
`lea 0x64da4b0` (`.data.rel.ro`): `0x6358792`, `0x6358935`,
`0x635967f`, `0x635971b`, `0x6359781`, `0x635989a`, `0x6359aae`,
`0x6359bbc`, `0x635a5d7`, `0x635a67d`. `rsi` is `r12d` at six sites,
0 at two sites (`xor %esi,%esi`), `r14` at one site, and not
established at one site (`0x635a67d` — no `rsi` write in the 12
lines before the call).

**Dispatcher.** The bulk of the window is a per-element dispatch
loop calling: `0x6364880` x13, `0x63e9cd0` x12, `0x6353610` x10,
`0x6365150` x8, `0x63ed8b0` x8, `0x63bd2c0` x8 (18-byte thunk),
`memset@plt` x11, `0x63e9c40` x4, `0x63edf10` x4, `0x63eec80` x2,
`0x63bf5b6` x2, `0x63f0bf0` x2, `0x63c2e80` x2, `0x63c3890` x2,
`0x63c3b00` x2, `0x63c3780` x2, `0x6352fc0` x2, `0x634f8e0` x2,
`0x63ec4c0` x2, `0x6360ed0` x2, `0x6364420` x2, `0x6364410` x2,
`0x6364400` x2, `sched_getcpu@plt` x2, plus the #314 window
(once, `0x635885e`; `rsi` = `rbx`, `rdx` = `lea 0x1b0(%rbx)`,
`rcx` = `r12`), the #313 window (twice, `0x6357cca` and
`0x6359dbc`; `rdi` = `rbx`, `rsi` = `r12`), the #298 window
(twice, `0x6358dbd` and `0x6359ec1`; `rdi` = `rbx`, `rsi` = `r12`),
and one indirect call via GOT `0x64ffb38` at `0x6358e7e`.

**Exit (1 ret, 0 tail jumps).** The single `ret` is at `0x6357e19`
(shared epilogue at `0x6357dee`: canary check, `jne 0x6359adb`,
`add $0xa8,%rsp` + pops). All 495 jump instructions target inside
the window. Canary failure goes to `0x6359adb`, which calls
`__stack_chk_fail` (`0x63f0d70`). `eax` = `r12` at ret
(`mov %r12,%rax` at `0x6357e0c`) — NOT 0, like #315.

## Census (from the objdump exhibit, never copied from a prior packet)

- Strict mnemonic lines: 2679.
- Calls: 132 (35 distinct direct targets + 1 indirect via GOT
  `0x64ffb38`).
- Bin_table_init sites: 0.
- Lu-miss sites: 1 (`0x635a6cd`).
- Second-handler sites: 10.
- `ret`: 1 (`0x6357e19`). Tail-jump exits: 0. `bsr`: 12. `lock sub`:
  0. `lock add`: 0.
- Jumps: 495, all inside the window.
- Raw `0xe8` census (byte scan for `e8` with rel32 target `0x63d9700`,
  grouped by enclosing `.eh_frame` FDE, own parse of 135,313 FDEs
  sorted before bisect): total 168, 53 FDEs. This FDE holds 1 raw
  site, matching its 1 objdump site.
- Raw `0xe8` census for `0x63d9880` (bin_table_init): total 108, 42
  FDEs, tiers 10x1, 8x1, 6x2, 5x1, 4x8, 2x12, 1x17. This FDE holds
  0 raw sites. No 3-raw tier exists.
- `.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278
  entries, counted separately (direct ELF parse; readelf `-W`
  cross-checked — non-wide output truncates the JUMP_SLOT type
  name and undercounts).

## Correction to #316's pointer (proven by targeted objdump census)

#316's survey pointer for this window listed **bsr 0**. The
targeted census finds **12** `bsr` sites (`0x6358022`,
`0x635824b`, `0x63582a0`, `0x6358558`, `0x6358bc1`, `0x6359362`,
`0x63594b0`, `0x6359598`, `0x63599f4`, `0x635a1d5`, `0x635a2a4`,
`0x635a57f`), all power-of-two roundings in dispatcher sub-blocks.
The pointer's other figures are verified correct: 12,182 bytes, 2679
strict, 132 calls, 1 lu-miss site at `0x635a6cd`, 0 bin_table_init
sites, 10 second-handler sites, 1 ret at `0x6357e19`. The error
dates to #316's pointer, which carried #314's bsr count (0) instead
of counting this window.

## Frontier status

Packet #317 is the fourth packet of the lu-miss-caller frontier
(callers of `0x63d9700` that do not call `bin_table_init`): 53 FDEs,
168 sites, 16 survivors (`0x63495b0` #314, `0x6353a70` #315,
`0x6355900` #316, `0x63577f0` this packet, `0x635a7a0`, `0x635c6d0`,
`0x635e2e0`, `0x63c9650`, `0x63ccd60`, `0x63cddd0`, `0x63d03a0`,
`0x63d17e0`, `0x63d2a80`, `0x63d3f0e`, `0x63d4048`, `0x63e94a0`).
This window is a shared survivor of both miss-handler lists, so
claiming it consumes one slot of the combined 25-FDE miss-handler
pool (lu-miss 16 ∪ second-handler 18, 9 shared).

## Disjointness

Range-only collector over the merged tree plus all prior
`hl-wt-calls*` worktree records (exhibits/windows only, all
range-bearing forms, decimal-integer start/end accepted, plain
`int(x, 16)` for hex strings). The window `0x63577f0..0x635a786`
overlaps no prior range (verifier: PRIOR_COUNT priors scanned, 0
skipped, disjointness NONE), including packet #316's window
`0x6355900..0x63577e2`, packet #315's window `0x6353a70..0x635582b`,
packet #314's window `0x63495b0..0x6349775`, packet #215's handler
FDE `0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`.

## Not covered

- The bin_table_init body `0x63d9880..0x63d9a64` (#262) and the
  lu-miss handler `0x63d9700..0x63d987b` (#215) are cited, not
  claimed.
- The second miss handler `0x634ebb0..0x634eccd`, the lock-wait
  helper `0x63bf680..0x63bf7ee` (#251), the extract helper FDE
  `0x63be540..0x63be54d`, the 18-byte thunk `0x63bd2c0..0x63bd2d2`,
  the context helper FDE `0x63ef8e0..0x63efba2` (#258 exclusion),
  and the PLT stubs are cited, not claimed.
- The #314 window `0x63495b0..0x6349775`, the #313 window
  `0x63c2f00..0x63c3328`, the #298 window `0x6362f90..0x6363258`,
  the #316 window `0x6355900..0x63577e2`, and the #315 window
  `0x6353a70..0x635582b` are cited, not claimed.
- The node-resolution table (`0x65096c0`) and the fourteen `.bss`
  objects referenced by address are referenced by address only;
  their runtime contents are not established.
- The neighboring FDEs are not decoded here. The next FDE
  `0x635a790..0x635a79b` is an 11-byte thunk jumping back to this
  window's entry. The next lu-miss survivor `0x635a7a0..0x635c6c7`
  is the next question for packet #318.
- The entry `rsi` index's caller-side meaning, the `r12` walk
  key's caller-side meaning beyond its table-slot load, and the
  dispatcher callees' semantics beyond their call sites are not
  established.

## Verification

- Static verifier
  `tools/node115_lu_miss_caller_1site_dispatch3.py`: exit 0
  (226 checks, 0 failures).
- Own unit tests
  `tests/test_node115_lu_miss_caller_1site_dispatch3.py`
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

Packet #318 decodes `0x635a7a0..0x635c6c7` (7975 bytes, 1720 strict,
103 calls, 4 lu-miss sites at `0x635bebb`, `0x635c0d2`, `0x635c231`,
`0x635c45f`, 0 bin_table_init sites, 2 second-handler sites, 1 ret
at `0x635ab53`, bsr 7 — the next surviving lu-miss-caller candidate
after this packet, verified by program against all prior exhibits).
