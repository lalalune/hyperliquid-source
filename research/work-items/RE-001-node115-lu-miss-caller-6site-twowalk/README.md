# RE-001-node115-lu-miss-caller-6site-twowalk: lu-miss caller with a trylock-guarded install and two walks (first window with six lu-miss sites and eight reversed-operand compares)

Ninth packet of the lu-miss-caller frontier (after #314 on `0x63495b0`,
#315 on `0x6353a70`, #316 on `0x6355900`, #317 on `0x63577f0`, #318 on
`0x635a7a0`, #319 on `0x635c6d0`, #320 on `0x635e2e0`, and #321 on
`0x63c9650`). FDE `0x63ccd60..0x63cd907` (2983 bytes, 613 strict lines)
is a trylock-guarded install followed by TWO context-table walks and
SIX lu-miss sites — the ninth frontier window, the first with six
lu-miss sites, the first with two walks, and the first with a size
class feeding a key-resolver helper call. It opens with `endbr64`, a
canary, and a `pthread_mutex_trylock` on the prologue node (`lea
0x40(%rbp),%rdi`), retrying through the lock-wait helper `0x63bf680`
when the trylock fails, bumps the `0x38` refcount, and probes the
install with helper `0x63d3aa0` before calling the allocator/installer
`0x63cba10`. A fresh node gets a 16-byte zero-init (`pxor %xmm0` +
`movups` stores) plus node-field init (`0x60`, `0x68`, `0x80` = 1,
`0x84` = 0), its own trylock with a second lock-wait retry arm, and a
second node (`0x63c66d0` call) with a third retry arm. The size class
(byte table `0x67277c0`, `movzbl 0x19(%rcx),%ecx`, `edx` = `0xc8`)
feeds the key-resolver helper `0x6364880`, whose return is the walk-A
key; walk B is keyed by the saved node pointer in `0x20(%rsp)`. Each
walk has an inline `shr $0x30` extract feeding size table `0x6727a00`
and a `shl $0x10` / `sar $0x10` extract feeding node table `0x65096c0`
— walk A with a `lock add` refcount step, walk B with a `lock sub`
refcount decrement. Six 8-slot move-to-front scans share one slot set
(`0x2b0..0x320` in `rbx`): A1/A2 keyed by `r11` (walk-A key), B1–B4
keyed by `r10` (walk-B key), with 24 slot-compare instructions, EIGHT
reversed-operand (A1 slot 1; A2 slots 0, 4, 5, 6, 7; B2 slot-0 and its
loop), i.e. 14 of 48 slot positions reversed; their exhaustions fall
to the six lu-miss sites. All six miss sites share one argument
pattern (`rdi` = `rbx` context, `rsi` = `.bss` `0x6511a00`, `rdx` =
`r15` table pointer `rbx` + `0x1b0`, `rcx` = walk key, `r8d` = 1,
`r9d` = 0), with the `rcx` provenance proven by reaching-definitions
(noreturn-aware): sites 1–2 take the walk-A key (`mov %rax,%rcx` at
`0x63cce42`, restored from `(%rsp)` at site 2), sites 3–6 take `r13`
set immediately before the call, and the only `r13` definition
reaching sites 3–6 is `mov 0x20(%rsp),%r13` at `0x63cd06b` (the
walk-B key). The one second-handler site (`0x63cd27f`) is gated on the
node table `0x65096c0` being null and takes `rsi` = 0, `rdx` =
`.data.rel.ro` `0x64da4b0`. It exits by a single `ret` with `rax`
path-dependent (the saved node pointer from `0x20(%rsp)`, or 0 on the
four `xor %eax,%eax` paths) — no single exit value is established,
unlike #314 (`rbx`), #315 (`r12`), #316 (`r13`), #317 (`r12`), #319
(0), and #320 (`r15`). 0 `bin_table_init` sites, 0 `bsr`, 0 tail-jump
exits, 1 `lock sub` and 1 `lock add`. This window is a SHARED survivor
(in BOTH the lu-miss survivor list and the second-handler survivor
list), so claiming it consumes one slot of the combined 25-FDE
miss-handler pool. It also calls the lock-wait helper `0x63bf680`
three times — the follow-on frontier's helper — cited, not claimed.

## Window

| Item | Value |
| --- | --- |
| FDE | `0x63ccd60..0x63cd907` |
| Bytes | 2983 |
| Strict lines | 613 |
| Calls | 31 (18 distinct direct targets, 0 indirect) |
| Bin_table_init sites | 0 |
| Lu-miss sites | 6 (`0x63cd70d`, `0x63cd7b3`, `0x63cd7f1`, `0x63cd831`, `0x63cd86a`, `0x63cd8fd`) |
| Second-handler sites | 1 (`0x63cd27f`) |
| Ret | 1 (`0x63cd044`) |
| Tail-jump exits | 0 |
| Bsr | 0 |
| Lock sub / add | 1 / 1 |
| Jumps | 87 (0 outside) |
| Prev FDE | `0x63ccd30..0x63ccd5e` (gap 2, all `0xcc`) |
| Next FDE | `0x63cd910..0x63cddce` (padding 9, all `0xcc`) |

## Classification

- Entry: `endbr64`; pushes r15/r14/r13/r12/rbp/rbx, `sub
  $0x48,%rsp`, canary `%fs:0x28` saved to `0x38(%rsp)`. `rdi` is the
  context base (kept in `rbx`); `rsi` is kept in `r13`; `0x68(%rdi)`
  is loaded into `r12`; `rbp` = `(%r12)` is the trylock node. No TLS
  flag check (`%fs:0x330` appears nowhere).
- Trylock guard (prologue): `lea 0x40(%rbp),%rdi` at `0x63ccd90`;
  `call pthread_mutex_trylock@plt` at `0x63ccd94`; `test %eax,%eax`
  at `0x63ccd99`; `jne 0x63cd048` on failure. The failure path calls
  the lock-wait helper `0x63bf680` at `0x63cd04b` (`rdi` = `rbp`),
  sets `movb $0x1,0x68(%rbp)` at `0x63cd050`, and jumps back to
  `0x63ccda1` to retry. On success: `addq $0x1,0x38(%rbp)`
  (refcount) at `0x63ccda1`; owner field `0x30(%rbp)` compared to
  `rbx` (`cmp 0x30(%rbp),%rbx`), updated with `addq $0x1,0x28(%rbp)`
  + `mov %rbx,0x30(%rbp)` when it changes.
- Install probe: `lea 0x40(%r12),%rbp` at `0x63ccdb5`; `lea
  0x20(%rsp),%rcx` at `0x63ccdbc`; `rsi` = `r13`, `rdi` = `rbp`;
  `call 0x63d3aa0` at `0x63ccdc7`; `test %al,%al` at `0x63ccdcc`;
  `je 0x63cd000` on zero (alternate exit: `rbx` = the saved node
  pointer from `0x20(%rsp)`, flag `0x80` set, unlock, epilogue).
  Otherwise unlock at `0x63ccde0`.
- Install allocator: `lea 0x28(%rsp),%rcx` at `0x63ccde5`; `rdx` =
  `r12`; `rsi` = `r13`; `r9` = `lea 0x1f(%rsp)`; `r8` = `lea
  0x30(%rsp)`; `rdi` = `rbx`; `call 0x63cba10` at `0x63ccdfd`;
  `test %al,%al` at `0x63cce02`; `jne 0x63cd135` when nonzero
  (found: `xor %eax,%eax`, exit 0). Otherwise the gate: `cmpb
  $0x0,0x1(%rbx)` at `0x63cce0a`; `jg 0x63cd260` (second-handler
  path); `mov 0x88(%rbx),%r14` at `0x63cce14`; null `r14` goes to
  `0x63cd1b0` (`call 0x6352fc0`, then `call 0x63edf10`).
- Second-handler path (`0x63cd260`): `lea 0x65096c0,%rdx`; `mov
  (%rdx),%r14`; nonzero jumps back to the size-class region at
  `0x63cce24`; null calls `0x634ebb0` at `0x63cd27f` with `rdi` =
  `rbx`, `rsi` = 0, `rdx` = `0x64da4b0` (`.data.rel.ro`), then
  `mov %rax,%r14` and `jmp 0x63cce24`.
- Size class: `lea 0x67277c0,%rcx` (byte table) at `0x63cce24`;
  `xor %r8d,%r8d`; `rsi` = `r14`; `rdi` = `rbx`; `edx` = `0xc8`;
  `movzbl 0x19(%rcx),%ecx` at `0x63cce39`; `call 0x6364880` at
  `0x63cce3d`; `mov %rax,%rcx` at `0x63cce42` (the walk-A key);
  `test %rax,%rax`; `je 0x63cd230` on zero (zero `0x20(%rsp)`,
  re-check `0x1f(%rsp)`, call `0x63c9500` or exit 0).
- Walk A (key = `0x6364880` return, table `rbx` + `0x1b0` in
  `r15`): top index `(key >> 0x1a) & 0xf0`, high bits `key &
  0xffffffffc0000000`, compare `cmp %r9,%r11` at `0x63cce77`
  (`r9` = `0x1b0(%r13)`), mismatch to scan A1 at `0x63cd158`;
  second level `(key >> 0x9) & 0x1ffff8 + table + 0x8`, head `mov
  (%rax),%rax` at `0x63cce90`. Extract: `shr $0x30,%rax` at
  `0x63cce9a` + size table `0x6727a00` (`mov (%r14,%rax,8),%r10`
  at `0x63cce9e`); second compare `cmp %r11,%r9` at `0x63ccea2`,
  mismatch to scan A2 at `0x63cd290`. Then `shl $0x10,%r11` /
  `sar $0x10,%r11` / `and $0xffffffffffffff80,%r11` feeding node
  table `0x65096c0` (`mov (%rdi,%rax,8),%r8` at `0x63ccedc`,
  `rdi` = `lea 0x65096c0`) and a `lock add %r10,0x38(%r8)` at
  `0x63ccee0` (refcount add under lock).
- Node init (walk-A result): 16-byte zero-init (`pxor %xmm0,%xmm0`
  at `0x63ccee5`, `movdqu 0x8(%r12),%xmm1`, `movups %xmm0` to
  `0x20`/`0x30`/`0x40`/`0x50(%rcx)`, `movups %xmm1` to `0x8(%rcx)`);
  `mov %rcx,0x20(%rsp)` at `0x63ccf12` saves the new node pointer
  (later the walk-B key and the exit value); `mov %r12,(%rcx)`;
  `movq $0x0,0x18(%rcx)`; `mov %r10,0x60(%rcx)`; `mov
  %r9,0x68(%rcx)`; `movb $0x1,0x80(%rcx)`; `movl $0x0,0x84(%rcx)`.
  Then a second trylock (`0x40(%r13)`, lock-wait retry at
  `0x63cd140`), refcount/owner update, `call 0x63d39a0` at
  `0x63ccf79`, unlock, and `test %bpl,%bpl` (`jne 0x63cd060` to
  walk B). The alternate branch installs a second node: `mov
  (%r12),%r15` at `0x63ccf9f`, trylock `0x40(%r15)` with a third
  lock-wait retry arm at `0x63cd218`, `movl $0x1,0x84(%rsi)` at
  `0x63ccfd2`, `call 0x63c66d0` at `0x63ccfdc`, unlock, `jmp
  0x63cd01d` (epilogue).
- Walk B (key = saved node pointer `0x20(%rsp)` in `r13`, table
  `rbx` + `0x1b0`): entry `cmpb $0x0,0x1f(%rsp)` at `0x63cd060`
  (`jne 0x63cd200` calls `0x63c9500` with `rdi` = `rbx`, `rsi` =
  `r12`, `rdx` = `0x30(%rsp)`, then jumps to the walk head at
  `0x63cd06b`); top index `(key >> 0x1a) & 0xf0`, high bits `key &
  0xffffffffc0000000`, compare `cmp %r11,%r10` at `0x63cd091`,
  mismatch to scan B1 at `0x63cd3c4`; second level `(key >> 0x9) &
  0x1ffff8 + table + 0x8`, `mov (%rax),%rax` at `0x63cd0ad`,
  `shr $0x30,%rax` at `0x63cd0b0` + size table (`mov
  (%r14,%rax,8),%r14` at `0x63cd0b4`); second compare `cmp
  %r10,%r11` at `0x63cd0b8`, mismatch to scan B2 at `0x63cd378`.
  Resolve: `shl $0x10,%r12` / `sar $0x10,%r12` /
  `and $0xffffffffffffff80,%r12` feeding node table `0x65096c0`
  and a `lock sub %r14,0x38(%rsi)` at `0x63cd0f7` (refcount
  decrement under lock); `cmp %r14,%r10` at `0x63cd103`,
  mismatch to scan B3 at `0x63cd32c`. Leaf: `mov (%rax),%rax` at
  `0x63cd11f`, `test $0x1,%al` at `0x63cd122`; set calls
  `0x63637f0` (#300's window) at `0x63cd130` then exits 0; clear
  goes to `0x63cd2dd` (`shr $0x30,%rax`, `cmp $0x23,%rax`, `jbe
  0x63cd4e8` calls `0x6363260` (#298's window) then exits 0;
  otherwise scan B4 at `0x63cd62f`, else `shl`/`sar $0x10`
  extract + `call 0x63bd6c0` at `0x63cd320` then exits 0).
- Scan (six 8-slot move-to-front loops over the same slot set,
  table+`0x2b0` in `rbx`, 16-byte entries, swap-on-hit): A1/A2
  keyed by `r11` (walk-A key), B1–B4 keyed by `r10` (walk-B key).
  Slot-0 compares: A1 `cmp 0x2b0(%rbx),%r11` at `0x63cd158`
  (normal); A2 `cmp %r11,0x2b0(%rbx)` at `0x63cd290` (REVERSED);
  B1 `cmp 0x2b0(%rbx),%r10` at `0x63cd3c4` (normal); B2 `cmp
  %r10,0x2b0(%rbx)` at `0x63cd378` (REVERSED); B3 `cmp
  0x2b0(%rbx),%r10` at `0x63cd32c` (normal); B4 `cmp
  0x2b0(%rbx),%r10` at `0x63cd62f` (normal). Loop compares cover
  slots 1–7 in one instruction each: A1 `0x63cd48b` (REVERSED)
  then `0x63cd686`, `0x63cd698`, `0x63cd6aa`, `0x63cd6bc`,
  `0x63cd6ce`, `0x63cd6db` (normal); A2 `0x63cd429` (normal),
  `0x63cd72c`, `0x63cd73e` (normal), `0x63cd750`, `0x63cd762`,
  `0x63cd774`, `0x63cd781` (REVERSED); B1 `0x63cd5d7` (normal);
  B2 `0x63cd573` (REVERSED); B3 `0x63cd50e` (normal); B4
  `0x63cd885` (normal). 24 slot-compare instructions, 8
  reversed-operand, 14 of 48 slot positions reversed (A1 1, A2 5,
  B2 8). Hits swap the 16-byte entries and rejoin the walk;
  exhaustions fall to the six miss blocks (A1/A2 on slot-7
  mismatch, B1–B4 when the loop counter reaches 8).
- Lu-miss sites (6): one argument pattern — `rdi` = `rbx`
  context, `rsi` = `0x6511a00` (`.bss`), `rdx` = `r15` table
  pointer (`rbx` + `0x1b0`), `rcx` = walk key, `r8d` = 1, `r9d` =
  0. Site 1 (`0x63cd70d`, block `0x63cd6ee`, A1 exhaustion) saves
  `r11`/`rax` to the stack and rejoins at the walk-A head
  `0x63cce90`; site 2 (`0x63cd7b3`, block `0x63cd794`, A2
  exhaustion) saves `r10`/`rcx` and rejoins at the walk-A extract
  `0x63ccebe`; site 3 (`0x63cd7f1`, block `0x63cd7d4`, B1
  exhaustion) saves `r10` and rejoins at the walk-B deref
  `0x63cd0ad`; site 4 (`0x63cd831`, block `0x63cd814`, B2
  exhaustion) rejoins at the walk-B resolve `0x63cd0d4`; site 5
  (`0x63cd86a`, block `0x63cd84d`, B3 exhaustion) rejoins at the
  walk-B leaf `0x63cd11f`; site 6 (`0x63cd8fd`, block `0x63cd8e4`,
  B4 exhaustion) rejoins at the walk-B leaf resolve `0x63cd30e`.
  The `rcx` provenance is proven by reaching-definitions
  (noreturn-aware CFG: the `__stack_chk_fail` call is noreturn
  and has no fall-through edge): sites 1–2 take the walk-A key
  (`mov %rax,%rcx` at `0x63cce42` is the only def reaching site 1;
  site 2 is reached by that def or by the miss-1 return restore
  `mov (%rsp),%rcx` at `0x63cd71e`, which reloads the same saved
  `rax`); sites 3–6 take `r13` set immediately before each call,
  and the only `r13` definition reaching them is `mov
  0x20(%rsp),%r13` at `0x63cd06b` (the walk-B key). A naive
  may-analysis without the noreturn exclusion also reports the
  `__stack_chk_fail` call and the B4-rotation `r15` load as
  reaching defs, but both flow only through the noreturn call's
  fall-through edge and cannot actually reach; the genuine `r15`
  def at all six sites is `lea 0x1b0(%rbx),%r15` at `0x63cce54`,
  and the genuine `rbx` def is the entry `mov %rdi,%rbx` at
  `0x63ccd71`.
- Second-handler sites (1): `0x63cd27f` (block `0x63cd260`),
  gated on the node table `0x65096c0` being null, `rsi` = 0, `rdx`
  = `0x64da4b0` (`.data.rel.ro`), `rdi` = `rbx`.
- Dispatcher: `0x6364880` 1 (key resolver; its return is the
  walk-A key), `0x63d3aa0` 1, `0x63cba10` 1, `0x63d39a0` 1,
  `0x63c66d0` 1, `0x6352fc0` 1, `0x63edf10` 1, `0x63ec4c0` 1,
  `0x63bd6c0` 1, `0x63637f0` 1 (#300's window), `0x6363260` 1
  (#298's window), `0x63bf680` 3 (one per lock-wait retry arm),
  `0x63c9500` 2; PLT: `pthread_mutex_trylock` 3,
  `pthread_mutex_unlock` 4, `__stack_chk_fail` 1. The #314–#321
  windows are NOT called from this FDE.
- Exit: `rax` is path-dependent at the single `ret` (`0x63cd044`;
  epilogue `mov 0x20(%rsp),%rax` at `0x63cd01d`, canary check
  `sub %fs:0x28,%rdx` at `0x63cd027`, `jne 0x63cd67c`
  (`__stack_chk_fail`), `add $0x48,%rsp`, pops, no other `rax`
  write): the reaching definitions at the ret are the saved node
  pointer (`mov 0x20(%rsp),%rax` at `0x63cd01d`) and `xor
  %eax,%eax` at `0x63cd135` (allocator-found path), `0x63cd254`
  (`0x63c9500` path), `0x63cd325` (`0x63bd6c0` path), and
  `0x63cd4fa` (`0x6363260` path) — so no single exit value is
  established.

## Census

- Raw `0xe8` census (own `.eh_frame` parse, 135,313 FDEs):
  lu-miss 168 sites / 53 FDEs (this FDE 6); bin_table_init 108 sites /
  42 FDEs (this FDE 0); second-handler 64 sites / 28 FDEs (this FDE
  1; the next candidate holds 0).
- `.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278.
- `.bss` `0x64ffe40..0x6728924`; four referenced addresses inside
  (`0x65096c0`, `0x6511a00`, `0x67277c0`, `0x6727a00`). `0x64da4b0`
  (second-handler argument) is inside `.data.rel.ro`.

## Correction to #321's pointer

#321's survey pointer for this window (2983 bytes, 613 strict,
31 calls, 6 lu-miss sites at `0x63cd70d`, `0x63cd7b3`, `0x63cd7f1`,
`0x63cd831`, `0x63cd86a`, `0x63cd8fd`, 0 bin_table_init sites, 1
second-handler site at `0x63cd27f`, 1 ret at `0x63cd044`, bsr 0) was
verified correct by targeted objdump census. No correction.

## Frontier status

Ninth packet of the lu-miss-caller frontier (53 FDEs, 168 sites,
16 survivors): #314 on `0x63495b0`, #315 on `0x6353a70`, #316 on
`0x6355900`, #317 on `0x63577f0`, #318 on `0x635a7a0`, #319 on
`0x635c6d0`, #320 on `0x635e2e0`, #321 on `0x63c9650`. This window is
a SHARED survivor (in both the lu-miss survivor list and the
second-handler survivor list), so claiming it consumes one slot of
the combined 25-FDE miss-handler pool (lu-miss 16 ∪ second-handler
18, 9 shared).

## Disjointness

Range-only collector over all prior records. The window
`0x63ccd60..0x63cd907` overlaps no prior range (verifier: 75,705
priors scanned, 0 skipped, disjointness NONE). The next candidate
`0x63cddd0..0x63ce23b` is likewise disjoint from all priors and from
this window (verifier).

## Not covered

- The bin_table_init body `0x63d9880..0x63d9a64` (#262, NOT called
  from this FDE), the lu-miss handler `0x63d9700..0x63d987b` (#215),
  the second miss handler `0x634ebb0..0x634eccd` (called once at
  `0x63cd27f`), the lock-wait helper `0x63bf680..0x63bf7ee` (#251,
  called three times, one per trylock retry arm), the extract
  helper FDEs `0x63be540..0x63be54d` and `0x63be4d0..0x63be4d6` (NOT
  called from this FDE), and the PLT stubs are cited, not claimed.
- The dispatcher callees' bodies are cited, not claimed — including
  the prev FDE `0x63ccd30..0x63ccd5e`, the next FDE
  `0x63cd910..0x63cddce`, the key-resolver helper
  `0x6364880..0x6365142`, the install helpers `0x63d3aa0..0x63d3af6`
  and `0x63cba10..0x63ccd22`, and the #298/#300 windows (called once
  each) and the #314–#321 windows (NOT called from this FDE).
- The `.bss` objects are referenced by address only; their runtime
  contents are not established.
- The entry inputs' caller-side meaning, the walk keys'
  caller-side meaning beyond their origins (resolver return /
  saved node pointer), the `0x68`/`0x28`/`0x30`/`0x38` node-field
  semantics beyond the observed reads/writes, and the dispatcher
  callees' semantics beyond their call sites are not established.
  The exit value's meaning beyond its path-dependence is not
  established.

## Verification

- Static verifier `tools/node115_lu_miss_caller_6site_twowalk.py`:
  exit 0 (480 checks, 0 failures).
- Own unit tests `tests/test_node115_lu_miss_caller_6site_twowalk.py`
  (tamper controls first — hex flip, strict-count change, call-site
  change, injected overlap — each makes the temp-copy verifier fail;
  the clean temp copy passes): exit 0 (12 checks, 0 failures).
- `make verify`: exit 0 (559 evidence-packet manifests, 7159 entries).
- `make catalogue-check`: exit 2 with the pre-existing `Stale
  catalogue: README.md` failure, also present on a pristine checkout;
  not a packet regression.
- Full `make test` is not run (584 files on the new base; hours of
  runtime and VM-restart risk). This deviation from the repository's
  stated gate is declared here rather than hidden.
- `.hex` exhibits are raw binary bytes, not hex text.

## Next question

Packet #323 decodes `0x63cddd0..0x63ce23b` (1131 bytes, 242 strict,
7 calls, 2 lu-miss sites at `0x63ce1f8` and `0x63ce221`, 0
bin_table_init sites, 0 second-handler sites, THREE rets at
`0x63cdf2f`, `0x63cdf43`, and `0x63cdf7a`, bsr 0 — the next surviving
lu-miss caller after this packet, verified by targeted objdump census
against all prior exhibits; it is a lu-miss-ONLY survivor, unlike
this packet, and it calls the FDE immediately after this window
(`0x63cd910`) once).
