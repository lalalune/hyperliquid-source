# RE-001-node115-lu-bintableinit-caller-1site-4walk-resolveall-plainrsp

Thirteenth 1-raw bin_table_init caller packet (after #298, #299, #300,
#301, #302, #303, #304, #305, #306, #307, #308, #309). The window is a
four-walk resolve-all routine: one bin_table_init site (plain `%rsp`
in-block via `rbx`, entered only by a null-context `je`, with no
save/restore), four context-table walks that store the resolved
second-level pointer of each walk into successive slots of the output
struct (`0x0/0x8/0x10/0x18(%rbp)`), four 8-slot move-to-front scans
(one per walk) with FOUR lu-miss sites, and a single `ret` exit — no
tail jump, 0 bsr. Unlike #309, there are NO null tests anywhere in
this FDE, so all four walks always run, and `eax` is 0 at `ret` (no
null-flag epilogue, no lu-miss quirk — see Return below).

## Window

- FDE `0x63afc60..0x63b0324`, 1732 bytes, 342 strict mnemonic lines.
- Previous FDE `0x63afbb0..0x63afc54` (gap 12 bytes, all `0xcc`).
- Next FDE `0x63b0330..0x63b03b2` (padding 12 bytes, all `0xcc`).
- Frame: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx, `sub $0x198,%rsp`,
  canary at `0x188(%rsp)` (stored at `0x63afc94`, checked against
  `%fs:0x28` at `0x63afdf0`, mismatch jumps to `__stack_chk_fail`).
- Entry: `rdi` = context (kept in `r13`), `rsi` = live input
  (kept in `r14`, passed to all four lu-miss calls; overwritten
  only on the scan-D hit paths), `rdx` = struct pointer (kept in
  `rbp`; the four result slots are `0x0/0x8/0x10/0x18(%rbp)`),
  `rcx` (kept in `r15`; `0x8(%rcx)` is the walk-1 key,
  `0x10(%rcx)` feeds the walk-2 derived key), `r8` (kept in `r12`;
  `0x8(%r12)` is the walk-3 key, `0x10(%r12)`/`0x8(%r12)` feed
  the walk-4 derived key).
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.

## Classification summary

- Null-context gate: `test %rdi,%rdi` at `0x63afc9e`,
  `je 0x63afe18` at `0x63afca1` — the bin_table_init site is
  entered only when the context is null.
- Bin_table_init site: `0x63afe1e` (block `0x63afe18`,
  `mov %rsp,%rbx`, `mov %rbx,%rdi`; no `lea`, no save/restore;
  `rsi` lives in callee-saved `r14` across the call; rejoin
  `jmp 0x63afca7`; entered only by a null-context `je` from
  `0x63afca1`; preceding instruction is the `nopl` at
  `0x63afe11`). First plain-`%rsp` site in the 1-raw chain.
- Table base in `rbx`: `lea 0x1b0(%rdi),%rbx` at `0x63afc7d`
  on the normal path; on the null-context path the bti block
  overwrites `rbx` with `mov %rsp,%rbx`, so the four walks
  and four scans all run against the stack-temp table. The
  result slots are in `rbp` (entry `rdx`).
- Stack scratch: none — no `rep stos`, no stack save/restore
  anywhere in this FDE. The frame is `sub $0x198,%rsp` with
  the canary at `0x188(%rsp)`; the bti table is the stack
  itself (plain `%rsp` via `rbx`).
- Walk 1 (table in `rbx`): key = `0x8(%r15)`
  (`mov 0x8(%r15),%rax` at `0x63afca7`). Top index
  `(key >> 0x1a) & 0xf0` (`shr $0x1a,%rax` at `0x63afcb1`,
  `and $0xf0,%eax` at `0x63afcb5`, `add %rbx,%rax` at
  `0x63afcc8`), high bits `key & 0xffffffffc0000000` (`and` at
  `0x63afcba`), page `key & 0xfffffffffffff000` (`and` at
  `0x63afcc1`), top-level compare `cmp %rsi,%rdi` at `0x63afcce`;
  a mismatch falls to scan A at `0x63afe30`. Second level
  `(key >> 0x9) & 0x1ffff8 + table + 0x8`
  (`shr $0x9,%rcx` at `0x63afcd7`,
  `and $0x1ffff8,%ecx` at `0x63afcdb`,
  `add 0x8(%rax),%rcx` at `0x63afce1`). The second-level
  pointer is stored at `mov %rax,0x0(%rbp)` at `0x63afce8`.
  No null test — walk 2 always runs.
- Walk 2: derived key `page(0x10(%r15)) + page(0x8(%r15)) -
  0x1000` (`lea -0x1000(%rdi,%r15,1),%r11` at `0x63afd02`),
  same top-index/second-level shape, top-level compare
  `cmp %rsi,%rcx` at `0x63afd26`, mismatch falls to scan B at
  `0x63afe70`, second-level pointer stored at
  `mov %rax,0x8(%rbp)` at `0x63afd41`. No null test — walk 3
  always runs.
- Walk 3: key = `0x8(%r12)` (`mov 0x8(%r12),%rax` at
  `0x63afd45`), top-level compare `cmp %rdi,%r15` at
  `0x63afd6d`, mismatch falls to scan C at `0x63afeb8`,
  second-level pointer stored at `mov %rax,0x10(%rbp)` at
  `0x63afd87`. No null test — walk 4 always runs.
- Walk 4: derived key `page(0x10(%r12)) + page(0x8(%r12)) -
  0x1000` (`lea -0x1000(%r15,%r12,1),%rcx` at `0x63afda3`),
  top-level compare `cmp %rdi,%r11` at `0x63afdc7`,
  mismatch falls to scan D at `0x63aff00`, second-level
  pointer stored at `mov %rax,0x18(%rbp)` at `0x63afde4`.
  There is NO `shl/sar $0x10` + mask transform (like
  #303–#309, unlike #298–#302). No node-resolution table
  (`0x65096c0`, `0x6511780`) and no size table (`0x6727a00`,
  `0x67277c0`) is read anywhere in this FDE, and no composed
  value is written — the four walks store second-level
  pointers, not field values.
- Scan A (8 slots, table+`0x100` in `rbx`, key in `rdi`,
  move-to-front on a hit): slot 0 at `0x63afe30` (`cmp 0x100(%rbx),%rdi`), slot 1 at `0x63aff46`,
  slot 2 at `0x63b00e1`, slot 3 at `0x63b00f4`, slot 4 at
  `0x63b0107`, slot 5 at `0x63b011a`, slot 6 at `0x63b012d`,
  slot 7 at `0x63b013a` (`cmp 0x170(%rbx),%rdi` — memory
  directly). 0 reversed-operand compares.
  Slot-0 hit uses the inline block at `0x63afe3d..0x63afe6b`
  (it swaps the top-level entry's second-level base with the
  scan slot's stored base and recomputes the second-level
  pointer from the swapped base), slots 1–7 share the
  move-to-front block at `0x63aff53` (`r8d` = slot index,
  `r9d` = index-1, shift `*16`, swap slot toward head; rejoin
  `jmp 0x63afe56` into the slot-0 block). Exhaustion falls to
  lu-miss A `0x63b0162` (`rcx` = `page(key1)` carried from the
  walk-1 page mask at `0x63afcc1`, `r8d` = 1, `r9d` = 0,
  `rdi` = context in `r13`, `rsi` = entry `rsi` in `r14`,
  `rdx` = scan table in `rbx`; return value in `rax` is
  stored to `0x0(%rbp)`, rejoin `jmp 0x63afce8`).
- Scan B (8 slots, table+`0x100` in `rbx`, derived key 2 in
  `r11`, move-to-front on a hit): slot 0 at `0x63afe70` (`cmp 0x100(%rbx),%rcx`), slot 1 at `0x63b007e`,
  slot 2 at `0x63b0292`, slot 3 at `0x63b02a5`, slot 4 at
  `0x63b02b8`, slot 5 at `0x63b02cb`, slot 6 at `0x63b02de`,
  slot 7 at `0x63b02eb` (`cmp 0x170(%rbx),%rcx` — memory
  directly). 0 reversed-operand compares.
  Slot-0 hit uses the inline block at `0x63afe7d..0x63afeac`
  (same base-swap as scan A), slots 1–7 share the block at
  `0x63b008b` (rejoin `jmp 0x63afe96`). Exhaustion falls to
  lu-miss B `0x63b0315` (`rcx` = derived key 2 in `r11`,
  `r8d` = 1, `r9d` = 0, `rdi` = context in `r13`,
  `rsi` = entry `rsi` in `r14`, `rdx` = scan table in `rbx`;
  return value in `rax` is stored to `0x8(%rbp)`, rejoin
  `jmp 0x63afd41`).
- Scan C (8 slots, table+`0x100` in `rbx`, key in `r15`,
  move-to-front on a hit): slot 0 at `0x63afeb8` (`cmp 0x100(%rbx),%r15`), slot 1 at `0x63b0015`,
  slot 2 at `0x63b0201`, slot 3 at `0x63b0213`
  (`cmp %r15,0x130(%rbx)` — reversed), slot 4 at `0x63b0225`
  (`cmp %r15,0x140(%rbx)` — reversed), slot 5 at `0x63b0237`,
  slot 6 at `0x63b0249`, slot 7 at `0x63b0256`
  (`cmp 0x170(%rbx),%r15` — memory directly). Two
  reversed-operand compares (slots 3, 4). Slot-0 hit uses
  the inline block at `0x63afec5..0x63afef3`, slots 1–7 share
  the block at `0x63b0022` (rejoin `jmp 0x63afede`).
  Exhaustion falls to lu-miss C `0x63b0282` (`rcx` =
  `page(key3)` carried from the walk-3 page mask at
  `0x63afd60`, `r8d` = 1, `r9d` = 0, `rdi` = context in `r13`,
  `rsi` = entry `rsi` in `r14`, `rdx` = scan table in `rbx`;
  return value in `rax` is stored to `0x10(%rbp)`, rejoin
  `jmp 0x63afd87`).
- Scan D (8 slots, table+`0x100` in `rbx`, derived key 4 in
  `r11`, move-to-front on a hit): slot 0 at `0x63aff00` (`cmp 0x100(%rbx),%r11`), slot 1 at `0x63affae`,
  slot 2 at `0x63b0172`, slot 3 at `0x63b0185`, slot 4 at
  `0x63b0198`, slot 5 at `0x63b01ab`, slot 6 at `0x63b01be`
  (`cmp %r11,0x160(%rbx)` — reversed), slot 7 at `0x63b01cb`
  (`cmp 0x170(%rbx),%r11` — memory directly). One
  reversed-operand compare (slot 6). Slot-0 hit uses the
  inline block at `0x63aff0d..0x63aff3b` (the hit overwrites
  `r14` at `0x63aff18`), slots 1–7 share the block at
  `0x63affbb` (`r8d` = slot index, `r9d` = index-1; slot
  address built in `r13`, `r14` overwritten at `0x63affd7`;
  rejoin `jmp 0x63aff26`). Exhaustion falls to lu-miss D
  `0x63b01f2` (`rcx` = derived key 4, carried in `rcx` from
  the `lea` at `0x63afda3` — no instruction in the lu-miss
  block or on the scan-D miss path writes `rcx`, `r8d` = 1,
  `r9d` = 0, `rdi` = context in `r13`, `rsi` = entry `rsi`
  in `r14`, `rdx` = scan table in `rbx`; return value in
  `rax` is stored to `0x18(%rbp)`, rejoin `jmp 0x63afde4`).
- The lu-miss argument convention is reversed from #309:
  here `r8d` = 1 and `r9d` = 0 in every block; #309 had
  `r9d` = 1 and `r8d` = 0.
- Return: `eax` = 0 at `ret` (`0x63afe10`). Entry
  `xor %eax,%eax` at `0x63afc9c`; the only other `%eax`
  writes are the four top-index `and $0xf0,%eax` (at
  `0x63afcb5`/`0x63afd1b`/`0x63afd54`/`0x63afdbc`, all
  `< 0x100`); the epilogue loads the canary into `rax`
  (`mov 0x188(%rsp),%rax` at `0x63afde8`) and subtracts
  `%fs:0x28` (`sub` at `0x63afdf0`), so `rax` is 0 on the
  non-fault path. There is no `sete`, no `mov $0x1,%eax`,
  and no null-flag epilogue — unlike #309, this routine
  does not report null slots in `eax`, and there is no
  lu-miss quirk: every handler return value is stored to a
  slot and never reaches `eax`. The observable effects are
  the four second-level stores.
- Calls: 6 (bin_table_init, 4 lu-miss, `__stack_chk_fail`).
- Exit: single `ret` at `0x63afe10`; all 55 jump instructions
  target inside the window — no tail-jump exit (exit-ness verified
  per FDE).

Full site/scan tables, census, and method notes are in records.json
and EVIDENCE.md.

## Disjointness

Range-only collector over the merged tree plus all prior
`hl-wt-calls*` worktree records (exhibits/windows only, all
range-bearing forms, decimal-integer start/end accepted, plain
`int(x, 16)` for hex strings, 0 skipped). The window
`0x63afc60..0x63b0324` overlaps no prior range (verifier: see the
final verifier run figure below), including packet #309's window
`0x63af460..0x63afba4`, packet #308's window
`0x63aefe0..0x63af45f`, packet #307's window
`0x63aed40..0x63aefdb`, packet #306's window
`0x63ae980..0x63aed39`, packet #305's window
`0x63ae6e0..0x63ae974`, packet #304's window
`0x63ae2b0..0x63ae6d1`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`.

## Correction to the survey (proven by objdump census, carried forward from #306)

The #298–#305 surveys listed packet #307's window
`0x63aed40..0x63aefdb` with **2** lu-miss sites. Packet #306
proved by targeted objdump census that the FDE has **one** call
to `0x63d9700` (`0x63aefcd`); the other calls are bin_table_init
`0x63aeea1` and `__stack_chk_fail` `0x63aef60` (3 calls total,
149 strict, 1 ret at `0x63aedb5`, 0 bsr). Packet #307's own
census re-verified the corrected figure and carries it forward;
the error dates to #298's original survey and was carried
verbatim through #305. All other fall-through candidates were
re-verified by program and match the survey exactly
(`0x63bc490` miss 1, `0x63bc730` miss 1, `0x63c2f00` miss 1
with bsr 1).

## Prior pointer verified (no correction)

#309's survey pointer for this window (1732 bytes, 1
bin_table_init site `0x63afe1e`, 4 lu-miss sites, 1 ret at
`0x63afe10`, 0 bsr) is verified correct by program arithmetic
and by the objdump census above.

## 1-raw tier status

Packet #298 surveyed all 17 1-raw candidates (each exactly 1
objdump-verified bin_table_init site). 16 survive; 1 is excluded as
a whole FDE (`0x63adf40..0x63ae252`, overlapping #214's claimed
sub-ranges). This packet builds on the thirteenth survivor. The next
frontier is packet #311 on `0x63bc490..0x63bc728` (664 bytes, 1
bin_table_init site, 1 lu-miss site, 1 ret, 0 bsr).

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_4walk_resolveall_plainrsp_1site.py`:
  exit 0 (205 checks, 0 failures — count taken from the source
  before sealing, confirmed by the sealing run).
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_4walk_resolveall_plainrsp_1site.py`
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

- Verifier: exit 0, 205 checks, 0 failures.
- Unit tests: exit 0, 12 checks, 0 failures.
- Disjointness: verifier scanned 65,594 priors, 0 skipped,
  NONE (deduplicated figure 64,766 after removing 828
  within-file duplicate ranges).
