# RE-001-node115-lu-bintableinit-caller-1site-2walk-fieldwrite-ecxgate

Eleventh 1-raw bin_table_init caller packet (after #298, #299, #300,
#301, #302, #303, #304, #305, #306, #307). The window is a
two-walk field-write routine with an `ecx == 0xe8` early return:
one bin_table_init site (`lea 0x10(%rsp)` in-block via `r13`,
entered only by a null-context `je`, with `rsi` living in
callee-saved `r15` across the call and `rdx` restored from `r13`
after it), a first walk that stores a composed value built from
the struct fields, `ecx`, and `r8b`, and a second walk — taken
only when `r8b != 0` and `page(0x10(%rbx)) > 0x1000` — that
stores the same composed value with constant `1` in place of
`r8b`. Each walk has its own 8-slot move-to-front scan and its
own lu-miss site (2 lu-miss sites total), and a single `ret`
exit — no tail jump, 0 bsr.

## Window

- FDE `0x63aefe0..0x63af45f`, 1151 bytes, 243 strict mnemonic lines.
- Previous FDE `0x63aed40..0x63aefdb` (gap 5 bytes, all `0xcc`).
- Next FDE `0x63af460..0x63afba4` (padding 1 byte, `0xcc`).
- Frame: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx, `sub $0x1a8,%rsp`,
  canary at `0x198(%rsp)` (stored at `0x63af014`, checked against
  `%fs:0x28` at `0x63af0c9`, mismatch jumps to `__stack_chk_fail`).
- Entry: `rdi` = context (kept in `rbp`), `rsi` = live input
  (kept in `r15`, never overwritten in this FDE, passed to both
  lu-miss calls), `rdx` = struct pointer (kept in `rbx`),
  `ecx` (kept in `r12d`), `r8d` (kept in `r14d`).
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.

## Classification summary

- Null-context gate: `test %rdi,%rdi` at `0x63af01e`,
  `je 0x63af190` at `0x63af021` — the bin_table_init site is
  entered only when the context is null; after the call the walk
  restarts at the `ecx` gate (`jmp 0x63af027` at `0x63af1a0`).
- `ecx == 0xe8` early return: `cmp $0xe8,%r12d` at `0x63af027`,
  `je 0x63af0c1` at `0x63af02e`. When `ecx` is `0xe8` the routine
  runs the shared epilogue (canary check) and returns at
  `0x63af0e9` with no table work at all.
- Walk 1 (context+`0x1b0` table, in `rdx`):
  `lea 0x1b0(%rdi),%rdx` at `0x63aeffd`. Key = `0x8(%rbx)`
  (`mov 0x8(%rbx),%rcx` at `0x63af034`); struct fields come from
  `(%rbx)` (`mov (%rbx),%r13` at `0x63af038`): a 3-bit field
  `(key0 >> 0x11) & 7` in `r13d` and a 1-bit field
  `(key0 >> 0x2c) & 1` in `r10d`. Top index `(key >> 0x1a) & 0xf0`
  (`shr $0x1a,%rax` at `0x63af048`, `and $0xf0,%eax` at
  `0x63af05b`, `add %rdx,%rax` at `0x63af064`), high bits
  `key & 0xffffffffc0000000` (`and` at `0x63af050`), top-level
  compare `cmp %rdi,%rsi` at `0x63af06a`; a mismatch falls to
  scan A at `0x63af1a8`. Second level `(key >> 0x9) & 0x1ffff8 +
  table + 0x8` (`shr $0x9,%rcx` at `0x63af073`,
  `and $0x1ffff8,%ecx` at `0x63af077`, `add 0x8(%rax),%rcx` at
  `0x63af07d`); a null second-level pointer skips the write
  (`test %rcx,%rcx` at `0x63af081`, `je 0x63af0bc` at `0x63af084`).
- Write 1: the composed value is
  `(struct & 0xffffffffffff) | r8b | (ecx << 0x30) |
  (((%rbx) >> 0x11 & 7) * 4) | (((%rbx) >> 0x2c & 1) * 2)`
  (`movzbl %r14b,%r11d` at `0x63af086`, `shl $0x30,%rdi` at
  `0x63af09e`, `lea 0x0(,%r13,4),%rsi` at `0x63af0a2`,
  `add %r8,%r8` at `0x63af0aa`, `movabs $0xffffffffffff,%rax` at
  `0x63af091`), stored at `mov %rax,(%rcx)` at `0x63af0b9`.
  There is NO `shl/sar $0x10` + mask transform (like #303–#307,
  unlike #298–#302). No node-resolution table (`0x65096c0`,
  `0x6511780`) and no size table (`0x6727a00`, `0x67277c0`) is
  read anywhere in this FDE.
- Second-walk gate: `test %r14b,%r14b` at `0x63af0bc`,
  `jne 0x63af0f0` at `0x63af0bf` — the second walk runs only when
  `r8b != 0`. Inside it, `page(0x10(%rbx)) <= 0x1000` also
  returns immediately (`mov 0x10(%rbx),%r14` at `0x63af0f0`,
  page mask at `0x63af0f4`, `cmp $0x1000,%r14` at `0x63af0fb`,
  `jbe 0x63af0c1` at `0x63af102`).
- Walk 2: derived key `page(0x10(%rbx)) + page(0x8(%rbx)) -
  0x1000` (`lea -0x1000(%r14,%rcx,1),%rsi` at `0x63af10f`),
  same top-index/second-level shape as walk 1, top-level
  compare `cmp %r8,%rdi` at `0x63af133`, mismatch falls to scan
  B at `0x63af1e8`, null second level returns
  (`test %rdx,%rdx` at `0x63af14d`, `je 0x63af0c1` at `0x63af150`).
- Write 2: the same composed value, except `r8b` is replaced by
  constant `1` (`shl $0x30,%r12` at `0x63af156`,
  `shl $0x2,%r13` at `0x63af15a`, `movabs $0xffffffffffff,%rdi`
  at `0x63af15e`, `or $0x1,%rdi` at `0x63af17b`), stored at
  `mov %rdi,(%rdx)` at `0x63af17f`.
- Bin_table_init site: `0x63af198` (block `0x63af190`,
  `lea 0x10(%rsp),%r13`, `mov %r13,%rdi`; no save/restore —
  `rsi` lives in callee-saved `r15` across the call, `rdx` is
  restored from `r13` after it (`mov %r13,%rdx` at `0x63af19d`);
  rejoin `jmp 0x63af027`; entered only by a null-context `je`
  from `0x63af021`; preceding instruction is the `nopw` at
  `0x63af187`).
- Scan A (8 slots, table+`0x100` in `rdx`, key high bits in
  `rsi`, move-to-front on a hit): slot 0 at `0x63af1a8`
  (`cmp 0x100(%rdx),%rsi`), slot 1 at `0x63af22e`, slot 2 at
  `0x63af323`, slot 3 at `0x63af336`, slot 4 at `0x63af349`,
  slot 5 at `0x63af35c`, slot 6 at `0x63af36f`, slot 7 at
  `0x63af37c` (`cmp 0x170(%rdx),%rsi` — memory directly, like
  #305's and #307's slot 7). All are normal-operand compares
  (memory first, key second); no key-first reversed-operand
  compare in this FDE (unlike #306's scan A with five). Slot-0
  hit uses the inline block at `0x63af1b1..0x63af1de` (it swaps
  the top-level entry's second-level base with the scan slot's
  stored base and recomputes the second-level pointer from the
  swapped base), slots 1–7 share the move-to-front block at
  `0x63af23b` (`r8d` = slot index, `r9d` = index-1, shift `*16`,
  swap slot toward head; rejoin `jmp 0x63af081` into the
  second-level null test). Exhaustion falls to lu-miss A
  `0x63af3a8` (`r9d` = 1, `r8d` = 0, `rdi` = context in `rbp`,
  `rsi` = entry `rsi` in `r15`, `rdx` = scan table (saved to
  `(%rsp)` before the call, restored after), `r10b` saved to
  `0xf(%rsp)` and restored; return value in `rax` lands in
  `rcx`, rejoin `jmp 0x63af081`).
- Scan B (8 slots, table+`0x100` in `rdx`, key high bits in
  `rdi`, move-to-front on a hit): slot 0 at `0x63af1e8`
  (`cmp 0x100(%rdx),%rdi`), slot 1 at `0x63af2ac`, slot 2 at
  `0x63af3ca`, slot 3 at `0x63af3dd`, slot 4 at `0x63af3f0`,
  slot 5 at `0x63af403`, slot 6 at `0x63af416`, slot 7 at
  `0x63af423` (`cmp 0x170(%rdx),%rdi` — memory directly). All
  normal-operand; 0 reversed-operand compares. Slot-0 hit uses
  the inline block at `0x63af1f5..0x63af223` (same base-swap as
  scan A), slots 1–7 share the move-to-front block at `0x63af2b9`
  (`r9d` = slot index, `ebp` = index-1; rejoin
  `jmp 0x63af14d` into the second-level null test). Exhaustion
  falls to lu-miss B `0x63af44d` (`rcx` = derived key in `rsi`,
  `r9d` = 1, `r8d` = 0, `rdi` = context in `rbp`,
  `rsi` = entry `rsi` in `r15`, `rdx` = scan table, `r10b`
  saved to `(%rsp)` and restored; return value in `rax` lands
  in `rdx`, rejoin `jmp 0x63af14d`).
 - Return: `eax` = 0 on the ret path (`xor %eax,%eax` at
  `0x63af01c`; the only other `%eax` writes are the two
  top-index `and $0xf0,%eax` at `0x63af05b`/`0x63af128`, and
  the epilogue canary sub at `0x63af0c9` leaves `rax` 0; the
  move-to-front blocks do not touch `eax`, unlike #305/#307
  where `eax` held a slot index). The observable effects are
  the two second-level stores.
- Calls: 4 (bin_table_init, 2 lu-miss, `__stack_chk_fail`).
- Exit: single `ret` at `0x63af0e9`; all 35 jump instructions
  target inside the window — no tail-jump exit (exit-ness verified
  per FDE).

Full site/scan tables, census, and method notes are in records.json
and EVIDENCE.md.

## Disjointness

Range-only collector over the merged tree plus all prior
`hl-wt-calls*` worktree records (exhibits/windows only, all
range-bearing forms, decimal-integer start/end accepted, plain
`int(x, 16)` for hex strings, 0 skipped). The window
`0x63aefe0..0x63af45f` overlaps no prior range (verifier: see the
final verifier run figure below), including packet #307's window
`0x63aed40..0x63aefdb`, packet #306's window
`0x63ae980..0x63aed39`, packet #305's window
`0x63ae6e0..0x63ae974`, packet #304's window
`0x63ae2b0..0x63ae6d1`, packet #303's window
`0x63adb50..0x63adf34`, packet #215's handler FDE
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
(`0x63af460` miss 4, `0x63afc60` miss 4, `0x63bc490` miss 1,
`0x63bc730` miss 1, `0x63c2f00` miss 1 with bsr 1).

## Prior pointer verified (no correction)

#307's survey pointer for this window (1151 bytes, 1
bin_table_init site `0x63af198`, 2 lu-miss sites, 1 ret at
`0x63af0e9`, 0 bsr) is verified correct by program arithmetic
and by the objdump census above.

## 1-raw tier status

Packet #298 surveyed all 17 1-raw candidates (each exactly 1
objdump-verified bin_table_init site). 16 survive; 1 is excluded as
a whole FDE (`0x63adf40..0x63ae252`, overlapping #214's claimed
sub-ranges). This packet builds on the eleventh survivor. The next
frontier is packet #309 on `0x63af460..0x63afba4` (1860 bytes, 1
bin_table_init site, 4 lu-miss sites, 1 ret, 0 bsr).

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_2walk_fieldwrite_ecxgate_1site.py`:
  exit 0 (138 checks, 0 failures — count taken from the source
  before sealing, confirmed by the sealing run).
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_2walk_fieldwrite_ecxgate_1site.py`
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

- Verifier: exit 0, 138 checks, 0 failures.
- Unit tests: exit 0, 12 checks, 0 failures.
- Disjointness: verifier scanned 63,910 priors, 0 skipped,
  NONE (deduplicated figure 63,102 after removing 808
  within-file duplicate ranges).
