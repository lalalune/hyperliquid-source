# RE-001-node115-lu-bintableinit-caller-1site-4walk-resolveall

Twelfth 1-raw bin_table_init caller packet (after #298, #299, #300,
#301, #302, #303, #304, #305, #306, #307, #308). The window is a
four-walk resolve-all routine: one bin_table_init site
(`lea 0x90(%rsp)` in-block via `rbp`, entered only by a
null-context `je`, with `r8` saved to the stack across the call),
four context-table walks that store the resolved second-level
pointer of each walk into successive slots of the output struct
(`0x0/0x8/0x10/0x18(%rbx)`), four 8-slot move-to-front scans
(one per walk) with FOUR lu-miss sites, and a single `ret` exit
— no tail jump, 0 bsr. The epilogue reports `1` in `eax` if any
of the four resolved pointers is null, else `0` (with one
quirk: on the lu-miss-D path the upper bytes of `eax` still hold
the handler's returned pointer — see Return below).

## Window

- FDE `0x63af460..0x63afba4`, 1860 bytes, 369 strict mnemonic lines.
- Previous FDE `0x63aefe0..0x63af45f` (gap 1 byte, `0xcc`).
- Next FDE `0x63afbb0..0x63afc54` (padding 12 bytes, all `0xcc`).
- Frame: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx, `sub $0x228,%rsp`,
  canary at `0x218(%rsp)` (stored at `0x63af494`, checked against
  `%fs:0x28` at `0x63af63f`, mismatch jumps to `__stack_chk_fail`).
- Entry: `rdi` = context (kept in `r13`), `rsi` = live input
  (kept in `r14`, never overwritten in this FDE, passed to all
  four lu-miss calls), `rdx` = struct pointer (kept in `rbx`),
  `rcx` (kept in `r15`; `0x8(%rcx)` is the walk-1 key),
  `r8` (saved to `0x20(%rsp)`; `page(r8)` feeds the walk-2
  derived key), `r9` (kept in `r12`; `0x8(%r12)` is the walk-3
  key, `0x10(%r12)`/`0x8(%r12)` feed the walk-4 derived key).
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.

## Classification summary

- Null-context gate: `test %rdi,%rdi` at `0x63af49e`,
  `je 0x63af6b8` at `0x63af4a1` — the bin_table_init site is
  entered only when the context is null.
- Bin_table_init site: `0x63af6c8` (block `0x63af6b8`,
  `lea 0x90(%rsp),%rbp`, `mov %rbp,%rdi`; `r8` is saved to
  `0x8(%rsp)` before the call and restored after it
  (`mov 0x8(%rsp),%r8` at `0x63af6cd`); `rsi` lives in
  callee-saved `r14` across the call; rejoin `jmp 0x63af4a7`;
  entered only by a null-context `je` from `0x63af4a1`;
  preceding instruction is the `nopw` at `0x63af667`).
- Table base in `rbp`: `lea 0x1b0(%rdi),%rbp` at `0x63af479`
  on the normal path; on the null-context path the bti block
  overwrites `rbp` with `lea 0x90(%rsp)`, so the four walks
  and four scans all run against the stack-temp table (like
  #306, where the table register was `r12`). The bti table
  temp `0x90(%rsp)` is referenced nowhere else in this FDE
  except the bti `lea` itself — the walks use `rbp`, never a
  direct `0x90(%rsp)` load.
- Stack scratch: after the bti rejoin, `rep stos` zeroes 128
  bytes at `0x10(%rsp)` (16 qwords: `lea 0x10(%rsp),%rdi` at
  `0x63af4a9`, `mov $0x10,%ecx` at `0x63af4ae`,
  `rep stos %rax,%es:(%rdi)` at `0x63af4b7`); entry `r8` is
  saved at `0x20(%rsp)` (`mov %r8,0x20(%rsp)` at `0x63af4ba`)
  and the walk-1 key (`0x8(%rcx)`) at `0x18(%rsp)`
  (`mov %rdx,0x18(%rsp)` at `0x63af4bf`); `movq $0,0x60(%rsp)`
  at `0x63af4c4` (inside the already-zeroed region). The bti
  table at `0x90(%rsp)` starts exactly where the zeroed region
  ends.
- Walk 1 (table in `rbp`): key = `0x18(%rsp)`
  (`mov 0x18(%rsp),%r11` at `0x63af4cd`). Top index
  `(key >> 0x1a) & 0xf0` (`shr $0x1a,%r11` at `0x63af4d8`,
  `and $0xf0,%r11d` at `0x63af4dc`, `add %rbp,%r11` at
  `0x63af4f0`), high bits `key & 0xffffffffc0000000` (`and` at
  `0x63af4e3`), page `key & 0xfffffffffffff000` (`and` at
  `0x63af4e9`), top-level compare `cmp %rcx,%rax` at `0x63af4f6`;
  a mismatch falls to scan A at `0x63af6e0`. Second level
  `(key >> 0x9) & 0x1ffff8 + table + 0x8`
  (`shr $0x9,%r15` at `0x63af4ff`,
  `and $0x1ffff8,%r15d` at `0x63af503`,
  `add 0x8(%r11),%r15` at `0x63af50a`). The second-level
  pointer is stored at `mov %rax,(%rbx)` at `0x63af511`
  BEFORE the null test (`test %rax,%rax` at `0x63af514`,
  `je 0x63af573` at `0x63af517` skips walk 2 when null).
- Walk 2: derived key `page(0x20(%rsp)) + page(0x18(%rsp)) -
  0x1000` (`lea -0x1000(%r11,%r15,1),%rdi` at `0x63af531`),
  same top-index/second-level shape, top-level compare
  `cmp %rsi,%rcx` at `0x63af555`, mismatch falls to scan B at
  `0x63af728`, second-level pointer stored at
  `mov %rax,0x8(%rbx)` at `0x63af56f`. No null test after
  walk 2 — walk 3 always runs.
- Walk 3: key = `0x8(%r12)` (`mov 0x8(%r12),%rax` at
  `0x63af573`), top-level compare `cmp %rcx,%r11` at
  `0x63af59b`, mismatch falls to scan C at `0x63af670`,
  second-level pointer stored at `mov %rax,0x10(%rbx)` at
  `0x63af5b5` before the null test (`test %rax,%rax` at
  `0x63af5b9`, `je 0x63af61b` at `0x63af5bc` skips walk 4 when
  null).
- Walk 4: derived key `page(0x10(%r12)) + page(0x8(%r12)) -
  0x1000` (`lea -0x1000(%rdx,%r12,1),%rcx` at `0x63af5d6`),
  top-level compare `cmp %r15,%r11` at `0x63af5fa`,
  mismatch falls to scan D at `0x63af770`, second-level
  pointer stored at `mov %rax,0x18(%rbx)` at `0x63af617`.
  There is NO `shl/sar $0x10` + mask transform (like
  #303–#308, unlike #298–#302). No node-resolution table
  (`0x65096c0`, `0x6511780`) and no size table (`0x6727a00`,
  `0x67277c0`) is read anywhere in this FDE, and no composed
  value is written — the four walks store second-level
  pointers, not field values.
- Scan A (8 slots, table+`0x100` in `rbp`, key high bits in
  `rax`, move-to-front on a hit): slot 0 at `0x63af6e0`
  (`cmp 0x100(%rbp),%rax`), slot 1 at `0x63af81e`, slot 2 at
  `0x63af944`, slot 3 at `0x63af957`, slot 4 at `0x63af96a`,
  slot 5 at `0x63af97d`, slot 6 at `0x63af990`, slot 7 at
  `0x63af99d` (`cmp 0x170(%rbp),%rax` — memory directly, like
  #305's and #307's slot 7). All are normal-operand compares
  (memory first, key second); 0 reversed-operand compares.
  Slot-0 hit uses the inline block at `0x63af6ed..0x63af71c`
  (it swaps the top-level entry's second-level base with the
  scan slot's stored base and recomputes the second-level
  pointer from the swapped base), slots 1–7 share the
  move-to-front block at `0x63af82b` (`r8d` = slot index,
  `r9d` = index-1, shift `*16`, swap slot toward head; rejoin
  `jmp 0x63af706` into the slot-0 block). Exhaustion falls to
  lu-miss A `0x63af9cd` (`rcx` = `page(key1)` in `r15`,
  `r9d` = 1, `r8d` = 0, `rdi` = context in `r13`,
  `rsi` = entry `rsi` in `r14`, `rdx` = scan table in `rbp`;
  return value in `rax` is stored to `0x0(%rbx)`, rejoin
  `jmp 0x63af511`).
- Scan B (8 slots, table+`0x100` in `rbp`, derived key 2 in
  `rcx`, move-to-front on a hit): slot 0 at `0x63af728`
  (`cmp 0x100(%rbp),%rcx`), slot 1 at `0x63af8e2`, slot 2 at
  `0x63afb0a`, slot 3 at `0x63afb1d`, slot 4 at `0x63afb30`,
  slot 5 at `0x63afb43` (`cmp %rcx,0x150(%rbp)` — reversed),
  slot 6 at `0x63afb56` (`cmp %rcx,0x160(%rbp)` — reversed),
  slot 7 at `0x63afb63` (`cmp 0x170(%rbp),%rcx` — memory
  directly). Two reversed-operand compares (slots 5–6).
  Slot-0 hit uses the inline block at `0x63af735..0x63af763`
  (same base-swap as scan A), slots 1–7 share the block at
  `0x63af8ef` (rejoin `jmp 0x63af74e`). Exhaustion falls to
  lu-miss B `0x63afb95` (`rcx` = derived key 2 in `rdi`,
  `r9d` = 1, `r8d` = 0, `rdi` = context in `r13`,
  `rsi` = entry `rsi` in `r14`, `rdx` = scan table in `rbp`;
  return value in `rax` is stored to `0x8(%rbx)`, rejoin
  `jmp 0x63af56f`).
- Scan C (8 slots, table+`0x100` in `rbp`, key high bits in
  `r11`, move-to-front on a hit): slot 0 at `0x63af670`
  (`cmp 0x100(%rbp),%r11`), slot 1 at `0x63af7b6`, slot 2 at
  `0x63af9dd`, slot 3 at `0x63af9f0`
  (`cmp %r11,0x130(%rbp)` — reversed), slot 4 at `0x63afa03`,
  slot 5 at `0x63afa16`, slot 6 at `0x63afa29`
  (`cmp %r11,0x160(%rbp)` — reversed), slot 7 at `0x63afa36`
  (`cmp 0x170(%rbp),%r11` — memory directly). Two
  reversed-operand compares (slots 3, 6). Slot-0 hit uses the
  inline block at `0x63af67d..0x63af6ac`, slots 1–7 share the
  block at `0x63af7c3` (rejoin `jmp 0x63af696`). Exhaustion
  falls to lu-miss C `0x63afa65` (`rcx` = `page(key3)` in
  `rdx`, `r9d` = 1, `r8d` = 0, `rdi` = context in `r13`,
  `rsi` = entry `rsi` in `r14`, `rdx` = scan table in `rbp`;
  return value in `rax` is stored to `0x10(%rbx)`, rejoin
  `jmp 0x63af5b5`).
- Scan D (8 slots, table+`0x100` in `rbp`, derived key 4 in
  `r11`, move-to-front on a hit): slot 0 at `0x63af770`
  (`cmp 0x100(%rbp),%r11`), slot 1 at `0x63af880`, slot 2 at
  `0x63afa75`, slot 3 at `0x63afa88`, slot 4 at `0x63afa9b`,
  slot 5 at `0x63afaae`, slot 6 at `0x63afac1`, slot 7 at
  `0x63aface` (`cmp 0x170(%rbp),%r11` — memory directly). All
  normal-operand; 0 reversed-operand compares. Slot-0 hit uses
  the inline block at `0x63af77d..0x63af7ab`, slots 1–7 share
  the block at `0x63af88d` (`r8d` = slot index, `r13d` =
  index-1; rejoin `jmp 0x63af796`). Exhaustion falls to
  lu-miss D `0x63afafa` (`rcx` = derived key 4, carried in
  `rcx` from the `lea` at `0x63af5d6` — no instruction in the
  lu-miss block or on the scan-D miss path writes `rcx`,
  `r9d` = 1, `r8d` = 0, `rdi` = context in `r13`,
  `rsi` = entry `rsi` in `r14`, `rdx` = scan table in `rbp`;
  return value in `rax` is stored to `0x18(%rbx)`, rejoin
  `jmp 0x63af617`).
- Return: `eax` = 1 if any of the four resolved slots is null
  (`mov $0x1,%eax` at `0x63af660`, reached by `je` from the
  first three `cmpq $0x0` tests at `0x63af61b`/`0x63af621`/
  `0x63af628`; `sete %al` at `0x63af634` records the fourth
  slot's null flag). If all four are non-null, `eax` is 0 on
  the direct and scan paths: the last `%eax` write is a
  top-index `and $0xf0,%eax` (at `0x63af54a`/`0x63af582`/
  `0x63af5ef`, all `< 0x100`), so `sete %al` leaves a clean
  0. EXCEPTION: on the lu-miss-D path `rax` still holds the
  handler's returned second-level pointer, so the upper bytes
  of `eax` are pointer bits and only the low byte is the flag
  — the verifier checks the exact `%eax` write list
  (`0x63af49c`, `0x63af4a7`, `0x63af54a`, `0x63af582`,
  `0x63af5ef`, `0x63af660`, `0x63af6a4`, `0x63af714`).
  The observable effects are the four second-level stores.
- Calls: 6 (bin_table_init, 4 lu-miss, `__stack_chk_fail`).
- Exit: single `ret` at `0x63af65f`; all 61 jump instructions
  target inside the window — no tail-jump exit (exit-ness verified
  per FDE).

Full site/scan tables, census, and method notes are in records.json
and EVIDENCE.md.

## Disjointness

Range-only collector over the merged tree plus all prior
`hl-wt-calls*` worktree records (exhibits/windows only, all
range-bearing forms, decimal-integer start/end accepted, plain
`int(x, 16)` for hex strings, 0 skipped). The window
`0x63af460..0x63afba4` overlaps no prior range (verifier: see the
final verifier run figure below), including packet #308's window
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
(`0x63afc60` miss 4, `0x63bc490` miss 1, `0x63bc730` miss 1,
`0x63c2f00` miss 1 with bsr 1).

## Prior pointer verified (no correction)

#308's survey pointer for this window (1860 bytes, 1
bin_table_init site `0x63af6c8`, 4 lu-miss sites, 1 ret at
`0x63af65f`, 0 bsr) is verified correct by program arithmetic
and by the objdump census above.

## 1-raw tier status

Packet #298 surveyed all 17 1-raw candidates (each exactly 1
objdump-verified bin_table_init site). 16 survive; 1 is excluded as
a whole FDE (`0x63adf40..0x63ae252`, overlapping #214's claimed
sub-ranges). This packet builds on the twelfth survivor. The next
frontier is packet #310 on `0x63afc60..0x63b0324` (1732 bytes, 1
bin_table_init site, 4 lu-miss sites, 1 ret, 0 bsr).

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_4walk_resolveall_1site.py`:
  exit 0 (179 checks, 0 failures — count taken from the source
  before sealing, confirmed by the sealing run).
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_4walk_resolveall_1site.py`
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

- Verifier: exit 0, 179 checks, 0 failures.
- Unit tests: exit 0, 12 checks, 0 failures.
- Disjointness: verifier scanned 64,752 priors, 0 skipped,
  NONE (deduplicated figure 63,934 after removing 818
  within-file duplicate ranges).
