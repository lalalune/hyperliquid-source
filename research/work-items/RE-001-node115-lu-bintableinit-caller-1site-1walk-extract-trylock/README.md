# RE-001-node115-lu-bintableinit-caller-1site-1walk-extract-trylock

Fifteenth 1-raw bin_table_init caller packet (after #298, #299, #300,
#301, #302, #303, #304, #305, #306, #307, #308, #309, #310, #311). The
window is a single-walk lookup-with-extract routine with a
trylock-guarded update: one bin_table_init site (`lea 0x20(%rsp)`
in-block via `rdi`, entered only by a null-context `je`, with `rsi`,
`r10` and `rdi` saved to the stack across the call), one
context-table walk that resolves a second-level pointer, a
`shl $0x10` / `sar $0x10` extract that decodes output values from
the resolved node descriptor, one 8-slot move-to-front scan with
ONE lu-miss site, and a trylock-guarded writeback phase whose
success path exits by a tail jump to `pthread_mutex_unlock` — the
first 1-raw caller with a tail-jump exit. Unlike #311, the index
path reads the node-resolution tables (`0x65096c0`, `0x6511780`)
to compute the mutex node, and unlike every prior 1-raw caller
except #311 its lu-miss `rsi` is the `.bss` address `0x6511a00`,
not entry `rsi` (see Lu-miss below). 0 bsr.

## Window

- FDE `0x63bc730..0x63bcb12`, 994 bytes, 212 strict mnemonic lines.
- Previous FDE `0x63bc490..0x63bc728` (#311, gap 8 bytes, all `0xcc`).
- Next FDE `0x63bcb20..0x63bcb77` (padding 14 bytes, all `0xcc`).
- Frame: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx, `sub $0x1b8,%rsp`,
  canary at `0x1a8(%rsp)` (stored at `0x63bc764`, checked against
  `%fs:0x28` at `0x63bc816` on the ret path and at `0x63bc910` on
  the unlock path, mismatch jumps to `__stack_chk_fail`).
- Entry: `rdi` = context (kept in `rbp`), `rsi` = lookup key,
  `rdx` = first output pointer (kept in `r15`; slot `0x0(%r15)`),
  `rcx` = second output pointer (kept in `r12`; slot `(%r12)`),
  `r8` = third output pointer (kept in `rbx`; slot `(%rbx)`),
  `r9` = fourth output pointer (kept in `r13`; slot `0x0(%r13)`),
  stack `0x1f0(%rsp)` = fifth output pointer (kept in `r10`; slot
  `(%r10)`), stack `0x1f8(%rsp)` = sixth output pointer (kept in
  `r14`; slot `(%r14)`).
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.
- No size class in this FDE (0 bsr, no `0x6727a00`/`0x67277c0`
  read), but the node-resolution tables `0x65096c0` and
  `0x6511780` ARE read on the index path (unlike #303–#311).

## Classification summary

- Null-context gate: `test %rbp,%rbp` at `0x63bc77e`,
  `je 0x63bc9d8` at `0x63bc781` — the bin_table_init site is
  entered only when the context is null.
- Bin_table_init site: `0x63bc9ec` (block `0x63bc9d8`,
  `lea 0x20(%rsp),%rdi` — the `lea` writes the table
  directly into `rdi`, so there is no separate
  `mov %rX,%rdi`; the block saves `r10` to `0x18(%rsp)`,
  `rsi` to `0x10(%rsp)`, `rdi` to `0x8(%rsp)` before the
  call and restores all three after it; rejoin
  `jmp 0x63bc787`; entered only by a null-context `je`
  from `0x63bc781`; preceding instruction is the `nopl`
  at `0x63bc9d1`).
- Table base in `rdi`: `add $0x1b0,%rdi` at `0x63bc749`
  on the normal path — it overwrites `rdi` itself; on the
  null-context path the bti block overwrites `rdi` with
  `lea 0x20(%rsp)`, so the walk and the scan run against
  the stack-temp table. The `0x20(%rsp)` temp is referenced
  nowhere else in this FDE except the `lea` itself.
- Stack scratch: none besides the bti block's three
  saves/restores — no `rep stos` anywhere in this FDE. The
  frame is `sub $0x1b8,%rsp` with the canary at `0x1a8(%rsp)`.
- Walk (single, table in `rdi`): key = entry `rsi`
  (`mov %rsi,%rax` at `0x63bc787`, `mov %rsi,%r8` at
  `0x63bc78a`). Top index `(key >> 0x1a) & 0xf0`
  (`shr $0x1a,%rax` at `0x63bc78d`, `and $0xf0,%eax` at
  `0x63bc798`, `add %rdi,%rax` at `0x63bc79d`), high bits
  `key & 0xffffffffc0000000` (`and` at `0x63bc791`),
  top-level compare `cmp %rcx,%r8` at `0x63bc7a3`; a
  mismatch falls to the scan at `0x63bc960`. Second level
  `(key >> 0x9) & 0x1ffff8 + table + 0x8`
  (`shr $0x9,%rsi` at `0x63bc7ac`,
  `and $0x1ffff8,%esi` at `0x63bc7b0`,
  `add 0x8(%rax),%rsi` at `0x63bc7b6`). The second-level
  pointer is loaded into `rdi` at `0x63bc7bd` — it is NOT
  stored to an output slot (unlike #309/#310, where each
  walk stored its resolved pointer); it feeds the extract.
- Extract (from the second-level value in `rdi`):
  `shl $0x10,%rdi` at `0x63bc7c0`, `mov %rdi,%r8` at
  `0x63bc7c4`, `sar $0x10,%r8` at `0x63bc7c7` (sign-extended
  48-bit value), `and $0xffffffffffffff80,%r8` at `0x63bc7cb`
  (low 7 bits cleared). `cmp $0x7fffff,%rdi` at `0x63bc7cf`,
  `jbe 0x63bc9a0` at `0x63bc7d6` — the zero path (all six
  outputs zeroed) is taken when the shifted value is
  `<= 0x7fffff`. Otherwise: `mov 0x10(%r8),%rax` at
  `0x63bc7dc`, `and $0xfffffffffffff000,%rax` at `0x63bc7e0`,
  `mov %rax,(%rbx)` at `0x63bc7e6` (page of the qword at
  node+0x10 into the `r8` output); `mov (%r8),%rbx` at
  `0x63bc7e9` (the node descriptor qword); `test $0x10,%bh`
  at `0x63bc7ec`, `jne 0x63bc840` at `0x63bc7ef` — the index
  path is taken when bit 12 of the descriptor is set. The
  flag path (bit 12 clear) stores `*r10` = 0, `*r13` = 0,
  `*r15` = 0, `*r12` = 1, `*r14` = 0 (`*rbx` keeps the page
  value) and returns via `ret`. On the index path:
  `shr $0x1c,%rbx` at `0x63bc840`,
  `and $0x3ff,%ebx` at `0x63bc850` — the index
  `(descriptor >> 0x1c) & 0x3ff` is stored to `0x0(%r15)`
  at `0x63bc856`; `mov (%r8),%r15` at `0x63bc859`,
  `shr $0x14,%r15` at `0x63bc85c`,
  `movzbl %r15b,%r10d` at `0x63bc860` — the byte
  `(descriptor >> 0x14) & 0xff` indexes a 40-byte-entry
  table at `0x6711b40` (`lea (%r10,%r10,4),%r9` at
  `0x63bc864`, `lea (%rdx,%r9,8),%r11` at `0x63bc868`, with
  `rdx` from `lea 0x3552f0(%rip),%rdx` at `0x63bc849`); the
  32-bit field at entry+0x10 (`mov 0x10(%r11),%ecx` at
  `0x63bc86c`) is stored to `(%r12)` at `0x63bc870`.
- The two referenced tables are `.bss` objects, not file
  data: `0x6511a00` (lu-miss `rsi`) and `0x6711b40`
  (extract table) both lie inside `.bss`
  (`0x64ffe40..0x6728924`, NOBITS). Their contents are
  runtime-populated and are not in the file; only the
  code's use of the addresses is claimed. The extract
  table's entry size (40 bytes) and field offset (+0x10)
  are read from the code, not from the table contents.
- Index path reads the node-resolution tables: `lea
  0x14ce42(%rip),%r8` at `0x63bc877` (`0x65096c0`) and
  `lea 0x154ee7(%rip),%rbx` at `0x63bc892` (`0x6511780`);
  the computed node pointer (`rbx`) plus `0x40` is the
  mutex (`lea 0x40(%rbx),%r15` at `0x63bc8b2`). The
  index computation is `mov (%r8,%rsi,8),%rax` (where
  `rsi` = descriptor low 12 bits), `mov (%rbx,%r10,4),%ebx`
  (where `r10` = the byte index), `add %rax,%rbx`, then
  `lea 0x0(,%rdi,8),%rax; sub %rdi,%rax; shl $0x5,%rax;
  add %rax,%rbx` (where `rdi` = descriptor >> 0x26,
  masked to 6 bits).
- Trylock-guarded update: `call pthread_mutex_trylock@plt`
  at `0x63bc8b9` (`rdi` = mutex node, `0x63f17b0`).
  `test %eax,%eax` at `0x63bc8c3`; on failure
  (`jne 0x63bc940` at `0x63bc8c5`) the lock-wait helper
  `0x63bf680` is called (`rdi` = mutex node), `movb $1,
  0x68(%rbx)` marks the node contended, and control jumps
  back to `0x63bc8c7` to retry the locked section. On
  success: `addq $1,0x38(%rbx)`; owner bookkeeping at
  `0x30(%rbx)` (compared against the context in `rbp`,
  `je 0x63bc8db` skips the count at `0x28(%rbx)` when the
  owner already matches); `mov (%r12),%rbp` then
  `imul 0xb0(%rbx),%rbp` stored to `(%r10)`;
  `sub 0x88(%rbx),%rbp` stored to `0x0(%r13)`;
  `mov 0xc0(%rbx),%rax` — if null (`je 0x63bca08` at
  `0x63bc8ff`) the fallback helper `0x63abd00` is called
  with `rdi` = `rbx+0xc8` (`lea 0xc8(%rbx),%rdi` at
  `0x63bca08`); a zero return stores 0 to `(%r14)`,
  otherwise `0x8(%rax)` is stored to `(%r14)`.
  `movb $0,0x68(%rbx)` clears the contended flag. The
  success path then exits by the tail jump (see Exit).
- Scan (single 8-slot move-to-front, table+`0x100` in
  `rdi`, key in `r8`): slot 0 at `0x63bc960`
  (`cmp 0x100(%rdi),%r8`), slot 1 at `0x63bca2e`, slot 2
  at `0x63bca7a`, slot 3 at `0x63bca89`
  (`cmp %r8,0x130(%rdi)` — reversed), slot 4 at
  `0x63bca98`, slot 5 at `0x63bcaa7`, slot 6 at `0x63bcab6`
  (`cmp %r8,0x160(%rdi)` — reversed), slot 7 at `0x63bcac3`
  (`cmp 0x170(%rdi),%r8` — memory directly) — two
  reversed-operand compares (slots 3, 6). Slot-0 hit uses
  the inline block at `0x63bc96d..0x63bc99b` (it swaps the
  top-level entry's second-level base with the scan slot's
  stored base and recomputes the second-level pointer from
  the swapped base, rejoining at `0x63bc7bd`); slots 1–7
  share the block at `0x63bca37` (`r11d` = slot index,
  `r9d` = index-1, shift `*16`, swap slot toward head),
  rejoining at `0x63bc974` into the slot-0 block.
  Exhaustion falls to lu-miss `0x63bcafe`.
- Lu-miss site (1): block `0x63bcae0`, call at `0x63bcafe`
  (`e8 fd cb 01 00` -> `0x63d9700`), rejoin
  `jmp 0x63bc7bd` at `0x63bcb08`. Arguments: `rdi` = `rbp`
  (entry context), `rsi` = `0x6511a00` via
  `lea 0x154f16(%rip),%rsi` at `0x63bcae3` (a `.bss`
  address — NOT entry `rsi`, like #311 and unlike
  #298–#310), `rdx` = `rdi` (scan table), `rcx` = entry
  `rsi` (`mov %rsi,%rcx` at `0x63bcae0` — `rsi` is still
  the entry key on the miss path, since the
  `shr $0x9,%rsi` at `0x63bc7ac` runs only on the
  top-level-match path), `r8d` = 1, `r9d` = 0. The return
  value in `rax` is the second-level pointer, which feeds
  the extract at `0x63bc7bd`.
- Exit: TWO exits. (1) Single `ret` at `0x63bc83e`
  (shared epilogue at `0x63bc816`: canary check,
  `add $0x1b8,%rsp` + pops) — taken by the flag path and
  the zero path. (2) Tail jump at `0x63bc93b`
  (`jmp 0x63f0b70`, `pthread_mutex_unlock@plt`) — taken by
  the trylock-success path after `mov %r15,%rdi`
  (the mutex node) and the same canary check + pops at
  `0x63bc910..0x63bc939`. All 27 jump instructions target
  inside the window except this one tail jump
  (exit-ness verified per FDE). Canary failure goes to
  `0x63bcb0d`, which calls `__stack_chk_fail`
  (`0x63f0d70`). `eax` = 0 at both exits: entry
  `xor %eax,%eax` at `0x63bc76c`; the only other `%eax`
  write is the top-index `and $0xf0,%eax` at `0x63bc798`
  (`test %eax,%eax` at `0x63bc8c3` only reads the trylock
  result); both epilogues load the canary into `rax` and
  subtract `%fs:0x28`, so `rax` is 0 on the non-fault
  path. There is no `sete`, no `mov $0x1,%eax`, and no
  null-flag epilogue. The observable effects are the six
  output stores (`*r10`, `*r13`, `*rbx`, `*r12`, `*r15`,
  `*r14`) plus the mutex-guarded counter/owner updates.

## Census (from the objdump exhibit, never copied from a prior packet)

- Strict mnemonic lines: 212.
- Calls: 6 (1 bin_table_init + 1 lu-miss + 1
  `pthread_mutex_trylock` + 1 lock-wait helper + 1 fallback
  helper + 1 `__stack_chk_fail`).
- Bin_table_init sites: 1 (`0x63bc9ec`), `lea 0x20(%rsp)` in-block.
- Lu-miss sites: 1 (`0x63bcafe`).
- `ret`: 1 (`0x63bc83e`). Tail-jump exits: 1 (`0x63bc93b` ->
  `pthread_mutex_unlock`). `bsr`: 0. `lock sub`: 0.
  `lock add`: 0.
- Raw `0xe8` census (byte scan for `e8` with rel32 target `0x63d9880`,
  grouped by enclosing `.eh_frame` FDE, own parse of 135,313 FDEs
  sorted before bisect): total 108, tiers 10x1, 8x1, 6x2, 5x1, 4x8,
  2x12, 1x17. This FDE holds 1 raw site, matching its 1 objdump
  site. No 3-raw tier exists.
- `.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278
  entries, counted separately (direct ELF parse; readelf `-W`
  cross-checked — non-wide output truncates the JUMP_SLOT type
  name and undercounts).

## 1-raw tier status

Packet #298 surveyed all 17 1-raw candidates (each exactly 1
objdump-verified bin_table_init site). 16 survive; 1 is excluded
as a whole FDE: `0x63adf40..0x63ae252` overlaps packet #214's
(lu nextnode) claimed sub-ranges `0x63adf71..0x63adf9d`,
`0x63ae014..0x63ae040`, `0x63ae088..0x63ae0cf`,
`0x63adfed..0x63ae014` in its records. The two standing
exclusions were re-verified: no 1-raw candidate falls inside
`0x63ed090..0x63ed862` (#260) or `0x63ef8e0..0x63efba2` (#258).
Survivors in address order: `0x6362f90` (#298), `0x6363260`
(#299), `0x63637f0` (#300), `0x6363d50` (#301), `0x6387420`
(#302), `0x63adb50` (#303), `0x63ae2b0` (#304), `0x63ae6e0`
(#305), `0x63ae980` (#306), `0x63aed40` (#307), `0x63aefe0`
(#308), `0x63af460` (#309), `0x63afc60` (#310), `0x63bc490`
(#311), `0x63bc730` (this packet), `0x63c2f00` (full
per-candidate census in records.json under `survey`).

**Correction to the survey (proven by objdump census, carried
forward from #306).** The #298–#305 surveys listed packet #307's
window `0x63aed40..0x63aefdb` with **2** lu-miss sites.
Packet #306 proved by targeted objdump census that the FDE has
**one** call to `0x63d9700` (`0x63aefcd`); the other calls are
bin_table_init `0x63aeea1` and `__stack_chk_fail` `0x63aef60`
(3 calls total, 149 strict, 1 ret at `0x63aedb5`, 0 bsr). Packet
#307's own census re-verified the corrected figure and carries
it forward; the error dates to #298's original survey and was
carried verbatim through #305. All other fall-through candidates
were re-verified by program and match the survey exactly
(`0x63c2f00` miss 1 with bsr 1).

**Prior pointer verified (no correction).** #311's survey pointer
for this window (994 bytes, 1 bin_table_init site `0x63bc9ec`,
1 lu-miss site, 1 ret at `0x63bc83e`, 0 bsr) is verified correct
by program arithmetic and by the objdump census above.

**Correction to #311's `.bss` figure (proven by own ELF parse).**
#311's EVIDENCE/README state `.bss` as
`0x64ffe40..0x6728d24`; the section header gives size
`0x228ae4`, so the end is `0x64ffe40 + 0x228ae4 = 0x6728924`.
Both referenced addresses (0x6511a00, 0x6711b40) still lie
inside. #311's verifier only checked containment, not the
exact end, so the error passed its gates; this packet's
verifier asserts the exact end.

**Survey method note.** The range-only collector used for the
claim check accepts start/end stored as decimal integers as well as
hex strings (plain `int(x, 16)` for strings, no regex gating on the
`0x` prefix — both failure modes found in #288/#290 are avoided),
accepts every range-bearing exhibit form in the corpus (`range`,
`fde_range`, `address_range` strings or lists; `start`/`end`,
`start_va`/`end_va_exclusive`, `start_va`/`end_va`, `address`/`end`,
`start`/`stop`, `start`/`end_exclusive` pairs), and asserts 0
range-like-but-unparseable entries. Scan-scope descriptors,
enclosing-fde annotations, census/cited-only subtrees, next-caller
pointers, and cfg edges are never collected. Exhibits carrying both
a `range` key and a `start`/`end` pair are counted twice by a naive
collector (848 within-file duplicate ranges in this corpus); the
deduplicated survey figure is 66,430 priors — the verdict is NONE
under either count.

## Disjointness

Range-only collector over the merged tree plus all prior
`hl-wt-calls*` worktree records (exhibits/windows only, all
range-bearing forms above, decimal-integer start/end accepted,
plain `int(x, 16)` for hex strings). The window
`0x63bc730..0x63bcb12` overlaps no prior range (verifier: 67,278
priors scanned, 0 skipped, disjointness NONE), including packet
#311's window `0x63bc490..0x63bc728`, packet #310's window
`0x63afc60..0x63b0324`, packet #309's window
`0x63af460..0x63afba4`, packet #308's window
`0x63aefe0..0x63af45f`, packet #307's window
`0x63aed40..0x63aefdb`, packet #306's window
`0x63ae980..0x63aed39`, packet #305's window
`0x63ae6e0..0x63ae974`, packet #304's window
`0x63ae2b0..0x63ae6d1`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`. (The verifier counts 848 within-file
duplicate ranges across the corpus; the deduplicated figure is
66,430 priors — the verdict is NONE under either count.)

## Not covered

- The bin_table_init body `0x63d9880..0x63d9a64` (#262) and the
  lu-miss handler `0x63d9700..0x63d987b` (#215) are cited, not
  claimed.
- The lock-wait helper `0x63bf680..0x63bf7ee` (#251), the
  fallback helper FDE `0x63abd00..0x63ac0cc`, and the
  `pthread_mutex_trylock` / `pthread_mutex_unlock` PLT stubs
  are cited, not claimed.
- The node-resolution tables (`0x65096c0`, `0x6511780`) are
  read in this FDE but not claimed. No size tables
  (`0x6727a00`, `0x67277c0`) are read in this FDE. The
  `.bss` objects at `0x6511a00` and `0x6711b40` are referenced
  by address only; their runtime contents are not established.
- The neighboring FDEs are not decoded here. The next FDE
  `0x63c2f00..0x63c3328` is the next question for packet #313.
- The entry `rsi` key's caller-side meaning, the `r8d`/`r9d`
  values' caller-side meaning, and the semantics of the six
  output values beyond the store sites are not established.
  The 40-byte table entries' other fields (besides +0x10)
  are not established. The mutex node's fields (+0x28/+0x30
  owner and counts, +0x68 contended flag, +0x88/+0xb0/+0xc0
  chain) are described only as the code uses them.
- The remaining 1-raw candidates are future packets
  (`0x63c2f00` is the last surviving 1-raw candidate).

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_1walk_extract_trylock_1site.py`:
  exit 0 (163 checks, 0 failures).
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_1walk_extract_trylock_1site.py`
  (tamper controls first — hex flip, strict-count change, call-site
  change, injected overlap — each makes the temp-copy verifier fail;
  the clean temp copy passes): exit 0 (12 checks, 0 failures). The
  test harness uses lean temp copies (verifier + packet dir +
  symlinked binary only); a full worktree copy changes nothing the
  verifier reads.
- `make verify`: exit 0 (559 evidence-packet manifests, 7159
  entries).
- `make catalogue-check`: exit 2 with the pre-existing `Stale
  catalogue: README.md` failure, also present on a pristine
  checkout; not a packet regression.
- Full `make test` is not run (584 files on the new base; hours of
  runtime and VM-restart risk). This deviation from the repository's
  stated gate is declared here rather than hidden.
- `.hex` exhibits are raw binary bytes, not hex text.

## Sealing-run figures

- Verifier: exit 0, 163 checks, 0 failures.
- Unit tests: exit 0, 12 checks, 0 failures.
- Disjointness: verifier scanned 67,278 priors, 0 skipped,
  NONE (deduplicated figure 66,430 after removing 848
  within-file duplicate ranges).
