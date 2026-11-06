# RE-001-node115-lu-bintableinit-caller-1site-1walk-extract-sizeclass

Sixteenth and last 1-raw bin_table_init caller packet (after #298,
#299, #300, #301, #302, #303, #304, #305, #306, #307, #308, #309,
#310, #311, #312). The window is a single-walk lookup-with-extract
routine with a size class and a trylock-guarded update: one
bin_table_init site (`lea 0x10(%rsp)` in-block via `r15`, entered
only by a null-context `je`, with NO save/restore), one
context-table walk that resolves a second-level pointer, a
`shl $0x10` / `sar $0x10` extract that feeds a helper call
(`0x63be550`) directly, a three-path size-class computation
(small byte-table path, `bsr` path, huge `0xe8` path — the first
size class in the 1-raw chain), and a trylock-guarded vector
update whose success path calls `pthread_mutex_unlock` inside
the window and then exits by `ret` or by a tail jump to
`0x63d72b0`, depending on a flag byte. The window also opens
with an init guard (`cmpb $0x0,0x67125f0`, helper `0x63d7bd0`) —
the first init guard in the 1-raw chain. 1 bsr. Unlike #312, the
node-resolution tables (`0x65096c0`, `0x6511780`) are NOT read
here, and unlike #311/#312 the lu-miss `rsi` is still the `.bss`
address `0x6511a00` (like #311/#312, not entry `rsi`).

## Window

- FDE `0x63c2f00..0x63c3328`, 1064 bytes, 230 strict mnemonic lines.
- Previous FDE `0x63c2e80..0x63c2f00` (gap 0).
- Next FDE `0x63c3330..0x63c349b` (padding 8 bytes, all `0xcc`).
- Frame: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx, `sub $0x1a8,%rsp`,
  canary at `0x198(%rsp)` (stored at `0x63c2f2d`, checked against
  `%fs:0x28` at `0x63c30a7` on the ret path and at `0x63c3100` on
  the tail-jump path, mismatch jumps to `__stack_chk_fail`).
- Entry: `rdi` = context (kept in `rbp`), `rsi` = lookup key (kept
  in `r12`), `rdx` = first output pointer (kept in `r14`),
  `rcx` = size input (kept in `r13`), `r8` = second output
  pointer (kept in `rbx`).
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.
- The size class is stored to `0x8(%rsp)` on all three paths and
  consumed as `r8d` at `0x63c2ff8` (vector-index computation) and
  as `esi` at `0x63c3117` (tail-jump argument).

## Classification summary

- Init guard: `cmpb $0x0,0x67125f0` at `0x63c2f37`
  (`.bss` flag byte); nonzero jumps (`jne 0x63c30d0` at
  `0x63c2f3e`) to the helper `0x63d7bd0` (call at `0x63c30d0`,
  FDE `0x63d7bd0..0x63d7c32`, cited not claimed), then
  `lea 0x1b0(%rbp),%r15` at `0x63c30d5`,
  `test %rbp,%rbp` at `0x63c30dc`, `jne 0x63c2f54` at
  `0x63c30df` (rejoin the walk). If `rbp` is null after the
  init helper, control falls through to the bin_table_init
  block. First init guard in the 1-raw chain.
- Null-context gate: `test %rbp,%rbp` at `0x63c2f4b`,
  `je 0x63c30e5` at `0x63c2f4e` — the bin_table_init site is
  entered only when the context is null.
- Bin_table_init site: `0x63c30ed` (block `0x63c30e5`,
  `lea 0x10(%rsp),%r15` — the `lea` writes the table
  address into `r15`, then `mov %r15,%rdi` at `0x63c30ea`
  passes it to the call; there is NO save/restore in this
  block — the block is exactly four instructions
  (`lea`/`mov`/`call`/`jmp`); rejoin `jmp 0x63c2f54`;
  entered only by a null-context `je` from `0x63c2f4e`
  plus fall-through from the init-guard path at
  `0x63c30df`; preceding instruction is the `jne` at
  `0x63c30df`).
- Table base in `r15`: `lea 0x1b0(%rbp),%r15` at `0x63c2f44`
  on the normal path (and again at `0x63c30d5` on the
  init-guard path) — on the null-context path the bti block
  overwrites `r15` with `lea 0x10(%rsp)`, so the walk and
  the scan run against the stack-temp table. The
  `0x10(%rsp)` temp is referenced nowhere else in this FDE
  except the `lea` itself.
- Stack scratch: none besides the size class at `0x8(%rsp)`
  and the helper-result byte at `0xf(%rsp)` — no `rep stos`
  anywhere in this FDE. The frame is `sub $0x1a8,%rsp` with
  the canary at `0x198(%rsp)`.
- Walk (single, table in `r15`): key = entry `rsi`
  (`mov %r12,%rax` at `0x63c2f54`, `mov %r12,%rcx` at
  `0x63c2f57`). Top index `(key >> 0x1a) & 0xf0`
  (`shr $0x1a,%rax` at `0x63c2f5a`, `and $0xf0,%eax` at
  `0x63c2f65`, `add %r15,%rax` at `0x63c2f6a`), high bits
  `key & 0xffffffffc0000000` (`and` at `0x63c2f5e`),
  top-level compare `cmp %rdi,%rcx` at `0x63c2f70`; a
  mismatch falls to the scan at `0x63c31e0`. Second level
  `(key >> 0x9) & 0x1ffff8 + table + 0x8`
  (`shr $0x9,%r12` at `0x63c2f79`,
  `and $0x1ffff8,%r12d` at `0x63c2f7d`,
  `add 0x8(%rax),%r12` at `0x63c2f84`). The second-level
  pointer is loaded into `r12` at `0x63c2f8b` — it is NOT
  stored to an output slot (like #311/#312); it feeds the
  extract.
- Extract (from the second-level value in `r12`):
  `shl $0x10,%r12` at `0x63c2f94`, `sar $0x10,%r12` at
  `0x63c2f98` (sign-extended 48-bit value),
  `and $0xffffffffffffff80,%r12` at `0x63c2f9c` (low 7 bits
  cleared). `mov %r12,%rdi` at `0x63c2fa0`, then `call
  0x63be550` at `0x63c2fa3` (FDE `0x63be550..0x63be5be`,
  cited not claimed) with `rsi` = entry `r8` (`rbx`,
  `mov %rbx,%rsi` at `0x63c2f91`) and `rdx` = entry `rdx`
  (`r14`, `mov %r14,%rdx` at `0x63c2f8e`). Unlike #311/#312,
  the extract feeds a helper call directly — there is no
  inline zero/flag/index output decoding in this FDE.
- Size class (first in the 1-raw chain; input = entry `rcx`
  in `r13`): `cmp $0x1000,%r13` at `0x63c2fa8`,
  `ja 0x63c3178` at `0x63c2faf`. Small path (`r13 <= 0x1000`):
  byte table `0x67277c0` (`lea` at `0x63c2fb5`), index
  `(r13+7)>>3` (`lea 0x7(%r13),%r11` at `0x63c2fbc`,
  `shr $0x3,%r11` at `0x63c2fc0`),
  `movzbl (%r15,%r11,1),%edi` at `0x63c2fc4`,
  `mov %edi,0x8(%rsp)` at `0x63c2fc9`. Bsr path
  (`0x1000 < r13 <= 0x7000000000000000`):
  `movabs $0x7000000000000000,%rcx` at `0x63c3178`,
  `cmp %r13,%rcx` at `0x63c3182`, `jb 0x63c3220` at
  `0x63c3185` (huge path), `lea -0x1(%r13,%r13,1),%rax`
  at `0x63c318b` (`2*r13-1`), `bsr %rax,%r8` at `0x63c31a1`,
  class computed from the bsr result plus masks
  (`cmovae`/`cmovb` clamps at `0x63c31ac`/`0x63c31c3`),
  `mov %r10d,0x8(%rsp)` at `0x63c31cc`,
  `jmp 0x63c2fcd`. Huge path (`r13 >
  0x7000000000000000`): `movl $0xe8,0x8(%rsp)` at
  `0x63c3220`, `jmp 0x63c2fcd`. All three paths store the
  class to `0x8(%rsp)`.
- Trylock-guarded update: `mov (%rbx),%rax` at `0x63c2fcd`,
  `mov (%rax),%r15` at `0x63c2fd0` (the mutex node),
  `lea 0x40(%r15),%rdi` at `0x63c2fd3`,
  `call pthread_mutex_trylock@plt` at `0x63c2fd7`
  (`0x63f17b0`). `test %eax,%eax` at `0x63c2fdc`; on failure
  (`jne 0x63c3160` at `0x63c2fde`) the lock-wait helper
  `0x63bf680` is called (`rdi` = mutex node),
  `movb $1, 0x68(%r15)` marks the node contended, and
  control jumps back to `0x63c2fe4` to retry the locked
  section. On success: `addq $1,0x38(%r15)`; owner
  bookkeeping at `0x30(%r15)` (compared against the context
  in `rbp`, `je 0x63c2ff8` skips the count at `0x28(%r15)`
  when the owner already matches); `mov 0x8(%rsp),%r8d`
  (the size class); vector update — `movdqu 0x30(%rbx),
  %xmm1`, `movdqu 0x20(%rbx),%xmm2`, tables `0x6713620`
  (`lea` at `0x63c300d`) and `0x6713d60` (`lea` at
  `0x63c301e`) indexed by the size class
  (`movhps (%rcx,%r8,8),%xmm0`,
  `movhps (%rdx,%r8,8),%xmm3`), `paddq` into `*rbx`
  `0x20..0x2f` and `0x30..0x3f`; the flag byte `0x6713601`
  (`cmpb` at `0x63c3025`, `je 0x63c3062` at `0x63c3046`)
  decides whether the `0x40..0x4f` and `0x50..0x5f`
  updates also run. Then `mov %rbx,%rsi`,
  `mov %rbp,%rdi`, `call 0x63d6690` at `0x63c3068`
  (FDE `0x63d6690..0x63d66ad`, cited not claimed);
  `movb $0x0,0x80(%rbx)`; the helper's return byte is
  saved to `0xf(%rsp)` (`mov %al,0xf(%rsp)` at
  `0x63c3077`); `mov (%rbx),%rbx`, `mov (%rbx),%rdi`,
  `movb $0x0,0x68(%rdi)`, `add $0x40,%rdi`,
  `call pthread_mutex_unlock@plt` at `0x63c3086`
  (`0x63f0b70`, inside the window — not a tail jump).
  After the unlock, `movzbl 0xf(%rsp),%esi` and
  `test %sil,%sil`: nonzero calls helper `0x63d6880`
  (`rdi` = `rbp` context, `rsi` = `r12`, `rdx` = `r14`,
  `rcx` = `r13`) at `0x63c314c (FDE
  `0x63d6880..0x63d6cb9`, cited not claimed), then rejoins
  the exit-flag check at `0x63c3099`.
- Exit flag: `lea 0x6717690,%r13` at `0x63c3099`,
  `cmpb $0x0,0x0(%r13)` at `0x63c30a0`,
  `jne 0x63c3100` at `0x63c30a5` — zero exits by `ret`,
  nonzero exits by the tail jump.
- Scan (single 8-slot move-to-front, table+`0x100` in
  `r15`, key in `rcx`): slot 0 at `0x63c31e0`
  (`cmp 0x100(%r15),%rcx`), slot 1 at `0x63c3236`, slot 2
  at `0x63c3295`, slot 3 at `0x63c32a4`, slot 4 at
  `0x63c32b3`, slot 5 at `0x63c32c2`
  (`cmp %rcx,0x150(%r15)` — reversed), slot 6 at `0x63c32d5`
  (`cmp %rcx,0x160(%r15)` — reversed), slot 7 at `0x63c32e2`
  (`cmp 0x170(%r15),%rcx` — memory directly) — two
  reversed-operand compares (slots 5, 6). Slot-0 hit uses
  the inline block at `0x63c31e9..0x63c3218` (it swaps the
  top-level entry's second-level base with the scan slot's
  stored base, stores the masked key to `(%rax)`, and
  recomputes the second-level pointer, rejoining at
  `0x63c2f8b`); slots 1–7 share the block at `0x63c323f`
  (`r8d` = slot index, `r9d` = index-1, shift `*16`, swap
  slot toward head), rejoining at `0x63c3202` into the
  slot-0 block. Exhaustion falls to lu-miss `0x63c3300`.
- Lu-miss site (1): block `0x63c3300`, call at `0x63c3319`
  (`e8 e2 63 01 00` -> `0x63d9700`), rejoin
  `jmp 0x63c2f8b` at `0x63c331e`. Arguments: `rdi` = `rbp`
  (entry context), `rsi` = `0x6511a00` via
  `lea 0x14e6f9(%rip),%rsi` at `0x63c3300` (a `.bss`
  address — NOT entry `rsi`, like #311/#312),
  `rdx` = `r15` (scan table), `rcx` = entry `rsi`
  (`mov %r12,%rcx` at `0x63c330a` — `r12` still holds the
  entry key on the miss path: the walk's `r12` writes
  (`0x63c2f79`/`0x63c2f7d`/`0x63c2f84`/`0x63c2f8b`) run
  only on the top-match path, the extract's `r12` writes
  (`0x63c2f94`/`0x63c2f98`/`0x63c2f9c`) run only after the
  second-level load, and the slot-0 hit block's `r12`
  writes (`0x63c3202`/`0x63c3209`) rejoin at `0x63c2f8b`
  and never reach the miss block — verified by the
  verifier's exact write-set check), `r8d` = 1, `r9d` = 0.
  The return value in `rax` is the second-level pointer,
  which feeds the extract at `0x63c2f8b`.
- Exit: TWO exits. (1) Single `ret` at `0x63c30cf`
  (shared epilogue at `0x63c30a7`: canary check,
  `add $0x1a8,%rsp` + pops) — taken when the exit flag
  byte `0x6717690` is 0. (2) Tail jump at `0x63c3132`
  (`jmp 0x63d72b0`, FDE `0x63d72b0..0x63d7367`) — taken
  when the flag byte is nonzero, after the canary check +
  pops at `0x63c3100..0x63c3130` and with `rdi` = `rbp`
  context, `rsi` = size class (`0x8(%rsp)`), `rdx` =
  `r14`. All 31 jump instructions target inside the window
  except this one tail jump (exit-ness verified per FDE).
  Canary failure goes to `0x63c3323`, which calls
  `__stack_chk_fail` (`0x63f0d70`). `eax` = 0 at both exits:
  entry `xor %eax,%eax` at `0x63c2f35`; the only other
  `%eax` write is the top-index `and $0xf0,%eax` at
  `0x63c2f65` (`test %eax,%eax` at `0x63c2fdc` only reads
  the trylock result); both epilogues load the canary into
  `rax` and subtract `%fs:0x28`, so `rax` is 0 on the
  non-fault path. There is no `sete`, no `mov $0x1,%eax`,
  and no null-flag epilogue. The observable effects are
  the helper calls, the size-class vector update, the
  mutex-guarded counter/owner updates, and the tail-jump
  arguments.

## Census (from the objdump exhibit, never copied from a prior packet)

- Strict mnemonic lines: 230.
- Calls: 10 (1 extract helper + 1 `pthread_mutex_trylock` +
  1 helper `0x63d6690` + 1 `pthread_mutex_unlock` + 1
  init-guard helper + 1 bin_table_init + 1 helper
  `0x63d6880` + 1 lock-wait helper + 1 lu-miss + 1
  `__stack_chk_fail`).
- Bin_table_init sites: 1 (`0x63c30ed`), `lea 0x10(%rsp)` in-block.
- Lu-miss sites: 1 (`0x63c3319`).
- `ret`: 1 (`0x63c30cf`). Tail-jump exits: 1 (`0x63c3132` ->
  `0x63d72b0`). `bsr`: 1 (`0x63c31a1`). `lock sub`: 0.
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

## 1-raw tier status — COMPLETE

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
(#311), `0x63bc730` (#312), `0x63c2f00` (this packet, #313).
This packet is the sixteenth and last surviving 1-raw
candidate: **the 1-raw tier is now exhausted (16 built + 1
excluded = 17)**.

**Multi-raw tiers re-surveyed by this packet (no survivors
either).** Own `.eh_frame` parse + raw-`0xe8` census +
prior-exhibit overlap check over 68,120 prior range entries
(merged tree plus all prior `hl-wt-calls*` worktree records,
claiming file named per overlap): all 25 multi-raw FDEs are
already claimed. 2-raw (12): 10 exact-claimed by prior 2-site
caller packets #288–#297, and 2 partial-overlap with claimed
sub-ranges (`0x63ed090..0x63ed862` overlaps #260's
`0x63ed090..0x63ed167`; `0x63ef8e0..0x63efba2` overlaps #258's
`0x63ef8e0..0x63ef92e` and `0x63efa50..0x63efa9e`). 4-raw (8):
all exact-claimed by #283–#287 and #289. 5-raw (1):
exact-claimed by #279. 6-raw (2): exact-claimed by #277/#278.
8-raw (1): exact-claimed by #276. 10-raw (1): exact-claimed by
#275. **The bin_table_init caller survey is complete: 42 FDEs
hold all 108 raw sites; there is no verified next candidate in
this survey. The next packet needs a new frontier, not yet
surveyed.**

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
were re-verified by program and match the survey exactly.

**Prior pointer verified (no correction).** #312's survey pointer
for this window (1064 bytes, 1 bin_table_init site `0x63c30ed`,
1 lu-miss site, 1 ret at `0x63c30cf`, bsr 1) is verified correct
by program arithmetic and by the objdump census above.

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
collector (858 within-file duplicate ranges in this corpus);
the deduplicated survey figure is 67,262 priors — the verdict is NONE
under either count.

## Disjointness

Range-only collector over the merged tree plus all prior
`hl-wt-calls*` worktree records (exhibits/windows only, all
range-bearing forms above, decimal-integer start/end accepted,
plain `int(x, 16)` for hex strings). The window
`0x63c2f00..0x63c3328` overlaps no prior range (verifier: 68,120
priors scanned, 0 skipped, disjointness NONE), including packet
#312's window `0x63bc730..0x63bcb12`, packet #311's window
`0x63bc490..0x63bc728`, packet #310's window
`0x63afc60..0x63b0324`, packet #309's window
`0x63af460..0x63afba4`, packet #308's window
`0x63aefe0..0x63af45f`, packet #307's window
`0x63aed40..0x63aefdb`, packet #306's window
`0x63ae980..0x63aed39`, packet #305's window
`0x63ae6e0..0x63ae974`, packet #304's window
`0x63ae2b0..0x63ae6d1`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`. (The verifier counts 858
within-file duplicate ranges across the corpus; the deduplicated
figure is 67,262 priors — the verdict is NONE under either count.)

## Not covered

- The bin_table_init body `0x63d9880..0x63d9a64` (#262) and the
  lu-miss handler `0x63d9700..0x63d987b` (#215) are cited, not
  claimed.
- The extract helper FDE `0x63be550..0x63be5be`, the init-guard
  helper FDE `0x63d7bd0..0x63d7c32`, the helper FDEs
  `0x63d6690..0x63d66ad` and `0x63d6880..0x63d6cb9`, the
  lock-wait helper `0x63bf680..0x63bf7ee` (#251), the tail-jump
  target FDE `0x63d72b0..0x63d7367`, and the
  `pthread_mutex_trylock` / `pthread_mutex_unlock` PLT stubs
  are cited, not claimed.
- The node-resolution tables (`0x65096c0`, `0x6511780`) are NOT
  read in this FDE (unlike #312). No size table (`0x6727a00`)
  is read in this FDE. The `.bss` objects at `0x6511a00`,
  `0x67125f0`, `0x6713601`, `0x6713620`, `0x6713d60`,
  `0x6717690`, and `0x67277c0` are referenced by address only;
  their runtime contents are not established.
- The neighboring FDEs are not decoded here. The next FDE
  `0x63c3330..0x63c349b` is not a bin_table_init caller (0 raw
  sites — it is outside the caller survey).
- The entry `rsi` key's caller-side meaning, the `r8d`/`r9d`
  values' caller-side meaning, and the semantics of the helper
  `0x63be550`'s outputs beyond the call site are not
  established. The size-class table's contents (byte table
  `0x67277c0`) and the vector tables' contents (`0x6713620`,
  `0x6713d60`) are runtime data and are not established. The
  mutex node's fields (+0x28/+0x30 owner and counts, +0x68
  contended flag, +0x80 byte) are described only as the code
  uses them.
- The 1-raw tier is exhausted and all 25 multi-raw caller FDEs
  are already claimed — there is no verified next candidate in
  the bin_table_init caller survey.

## Verification

- Static verifier
  `tools/node115_bintableinit_caller_1walk_extract_sizeclass_1site.py`:
  exit 0 (191 checks, 0 failures).
- Own unit tests
  `tests/test_node115_bintableinit_caller_1walk_extract_sizeclass_1site.py`
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

- Verifier: exit 0, 191 checks, 0 failures.
- Unit tests: exit 0, 12 checks, 0 failures.
- Disjointness: verifier scanned 68,120 priors, 0 skipped,
  NONE (deduplicated figure 67,262 after removing 858
  within-file duplicate ranges).
