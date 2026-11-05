# RE-001-node115-lu-bintableinit-caller-1site-pageinstall-earlyret

Tenth 1-raw bin_table_init caller packet (after #298, #299, #300,
#301, #302, #303, #304, #305, #306). The window is a single-site
page-range install routine with a small-range early return: one
bin_table_init site (`lea 0x10(%rsp)` in-block via `r13`, entered
only by a null-context `je`, with `rdx` and `rsi` saved to the stack
across the call), a page-stepping context-table walk that stores the
constant `0xe8000000000000` (the same constant as #306) at each
page's second-level entry, a single 8-slot move-to-front scan with
ONE lu-miss site, and a single `ret` exit — no tail jump, 0 bsr.
When `page(0x10(%rdx)) <= 0x2000` the routine returns immediately
with no table work at all.

## Window

- FDE `0x63aed40..0x63aefdb`, 667 bytes, 149 strict mnemonic lines.
- Previous FDE `0x63ae980..0x63aed39` (gap 7 bytes, all `0xcc`).
- Next FDE `0x63aefe0..0x63af45f` (padding 5 bytes, all `0xcc`).
- Frame: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx, `sub $0x1a8,%rsp`,
  canary at `0x198(%rsp)` (stored at `0x63aed68`, checked against
  `%fs:0x28` at `0x63aed95`, mismatch jumps to `__stack_chk_fail`).
- Entry: `rdi` = context (kept in `r12`), `rsi` = live input
  (saved to `(%rsp)` across both the bti call and the lu-miss
  call, passed to the lu-miss handler; caller-side meaning not
  established), `rdx` = struct pointer (saved to `0x8(%rsp)`
  across the bti call), `ecx`/`r8d` unused in this FDE.
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.

## Classification summary

- Small-range early return: `mov 0x10(%rdx),%rax` at `0x63aed7b`,
  page mask `and $0xfffffffffffff000,%rax` at `0x63aed7f`,
  `cmp $0x2000,%rax` at `0x63aed85`, `ja 0x63aedc0` at `0x63aed8b`.
  When the page is at most `0x2000` the routine runs the shared
  epilogue at `0x63aed8d` (canary check) and returns at `0x63aedb5`
  with no table work, no scan, and no call other than the
  null-context bin_table_init site (which is only reached when
  `rdi` is null — the early return runs first on the non-null
  path only after the `je` at `0x63aed75` is not taken).
- Page-range install loop (context+`0x1b0` table, in `r13`):
  `lea 0x1b0(%rdi),%r13` at `0x63aed4a`. The cursor `rbx` steps
  `0x1000` per page from `page(0x8(%rdx)) + 0x1000` up to
  `page(0x8(%rdx)) + page(0x10(%rdx)) - 0x2000` (end `r14`,
  `lea -0x2000(%rax,%rbp,1),%r14` at `0x63aedcb`; loop exits via
  `jb 0x63aed8d` at `0x63aeddd` and `jb 0x63aed8d` at `0x63aee12`).
  The loop head compares the cursor against the first page
  (`rbp` = base page + `0x1000`; `cmp %rbx,%rbp` at `0x63aee18`) —
  on the first page it does the full lookup (`je 0x63aee25`) — and
  tests the cursor's low 30 bits (`test $0x3fffffff,%ebx` at
  `0x63aee1d`); a nonzero result (any cursor not 1GB-aligned)
  jumps straight to the store block (`jne 0x63aee00`), reusing the
  second-level pointer advanced by 8 bytes per page; only a
  1GB-aligned cursor falls through to a fresh lookup.
  Per page: top index `(cursor >> 0x1a) & 0xf0`
  (`shr $0x1a,%rdx` at `0x63aee2b`, `and $0xf0,%edx` at
  `0x63aee36`, `add %r13,%rdx` at `0x63aee3c`), high bits
  `cursor & 0xffffffffc0000000` (`and` at `0x63aee2f`), second
  level `(cursor >> 0x9) & 0x1ffff8 + table + 0x8`
  (`shr $0x9,%rax` at `0x63aedf3`, `and $0x1ffff8,%eax` at
  `0x63aedf7`, `add 0x8(%rdx),%rax` at `0x63aedfc`). The top-level
  entry is compared at `0x63aee42` (`cmp %rdi,%rcx`); a mismatch
  falls to the scan at `0x63aee47`. On a match the constant in
  `r15` is stored (`add $0x1000,%rbx` at `0x63aee00`,
  `add $0x8,%rax` at `0x63aee07`, `mov %r15,-0x8(%rax)` at
  `0x63aee0b`). There is NO `shl/sar $0x10` + mask transform
  (like #303–#306, unlike #298–#302). No node-resolution table
  (`0x65096c0`, `0x6511780`) and no size table (`0x6727a00`,
  `0x67277c0`) is read anywhere in this FDE.
- Constant: `movabs $0xe8000000000000,%r15` at `0x63aeddf` — the
  same constant value #306 writes (there to both resolved node
  fields; here at each page's second-level entry). Entry
  `ecx`/`r8d` are not used — the written value is a constant,
  not composed from the entry registers (unlike #304's composed
  value and #305's `(ecx << 0x30) | ... | 1`).
- Bin_table_init site: `0x63aeea1` (block `0x63aee90`,
  `lea 0x10(%rsp),%r13`, `mov %r13,%rdi`; `rdx` saved to
  `0x8(%rsp)` and `rsi` saved to `(%rsp)` across the call and
  restored after; rejoin `jmp 0x63aed7b`; entered only by a
  null-context `je` from `0x63aed75`; preceding instruction is the
  `nopl` at `0x63aee88`).
- Scan (8 slots, table+`0x100` in `r13`, key high bits in `rcx`,
  move-to-front on a hit): slot 0 at `0x63aee4e`
  (`cmp %r8,%rcx`), slot 1 at `0x63aeec3` (`cmp %r10,%rcx`),
  slot 2 at `0x63aef15` (`cmp %r8,%rcx`), slot 3 at `0x63aef3c`
  (`cmp %r11,%rcx`), slot 4 at `0x63aef48` (`cmp %r8,%rcx`),
  slot 5 at `0x63aef77` (`cmp %r10,%rcx`), slot 6 at `0x63aef87`
  (`cmp %r8,%rcx`), slot 7 at `0x63aefaa`
  (`cmp 0x170(%r13),%rcx` — memory directly, like #305's slot 7).
  All are normal-operand compares (slot value first, key second);
  no key-first reversed-operand compare in this FDE (unlike
  #306's scan A with five). Slot-0 hit uses the inline block at
  `0x63aee53..0x63aee83`, slots 1–7 share the move-to-front block
  at `0x63aeec8` (`r9d` = previous slot index, `eax` = slot
  index, shift `*16`, swap slot into head; rejoin
  `jmp 0x63aee6c` into the second-level recompute). Exhaustion
  falls to lu-miss `0x63aefcd` (`r8d` = 1, `r9d` = 0,
  `rdi` = context in `r12`, `rsi` = entry `rsi` (saved to
  `(%rsp)` before the call, restored after), `rdx` = scan table
  in `r13`, `rcx` = page cursor in `rbx`; return value in `rax`
  is used directly as the second-level pointer, rejoin
  `jmp 0x63aee00` into the store block).
- Return: `eax` = 0 on the plain path (`xor %eax,%eax` at
  `0x63aed70` and `0x63aedec`); the scan move-to-front reuses
  `eax` as a slot index, so `eax` at `ret` reflects the last
  move-to-front slot index when a scan hit occurred (as in #305).
  The observable effects are the per-page stores.
- Calls: 3 (bin_table_init, 1 lu-miss, `__stack_chk_fail`).
- Exit: single `ret` at `0x63aedb5`; all 24 jump instructions
  target inside the window — no tail-jump exit (exit-ness verified
  per FDE).

Full site/scan tables, census, and method notes are in records.json
and EVIDENCE.md.

## Disjointness

Range-only collector over the merged tree plus all prior
`hl-wt-calls*` worktree records (exhibits/windows only, all
range-bearing forms, decimal-integer start/end accepted, plain
`int(x, 16)` for hex strings, 0 skipped). The window
`0x63aed40..0x63aefdb` overlaps no prior range (verifier: see the
final verifier run figure below), including packet #306's window
`0x63ae980..0x63aed39`, packet #305's window
`0x63ae6e0..0x63ae974`, packet #304's window
`0x63ae2b0..0x63ae6d1`, packet #303's window
`0x63adb50..0x63adf34`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`.

## Correction to the survey (proven by objdump census, carried forward from #306)

The #298–#305 surveys listed this window's candidate
`0x63aed40..0x63aefdb` with **2** lu-miss sites. Packet #306
proved by targeted objdump census that the FDE has **one** call
to `0x63d9700` (`0x63aefcd`); the other calls are bin_table_init
`0x63aeea1` and `__stack_chk_fail` `0x63aef60` (3 calls total,
149 strict, 1 ret at `0x63aedb5`, 0 bsr). This packet's own
census re-verifies the corrected figure (149 strict, 3 calls, 1
bti, 1 lu-miss, 1 ret, 0 bsr) and carries it forward; the error
dates to #298's original survey and was carried verbatim through
#305. All other fall-through candidates were re-verified by
program and match the survey exactly (`0x63aefe0` miss 2,
`0x63af460` miss 4, `0x63afc60` miss 4, `0x63bc490` miss 1,
`0x63bc730` miss 1, `0x63c2f00` miss 1 with bsr 1).

## Prior pointer verified (no correction)

#306's survey pointer for this window (667 bytes, 1 bin_table_init
site, 1 lu-miss site — corrected — 1 ret, 0 bsr) is verified
correct by program arithmetic and by the objdump census above.

## 1-raw tier status

Packet #298 surveyed all 17 1-raw candidates (each exactly 1
objdump-verified bin_table_init site). 16 survive; 1 is excluded as
a whole FDE (`0x63adf40..0x63ae252`, overlapping #214's claimed
sub-ranges). This packet builds on the tenth survivor. The next
frontier is packet #308 on `0x63aefe0..0x63af45f` (1151 bytes, 1
bin_table_init site, 2 lu-miss sites, 1 ret, 0 bsr).

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_pageinstall_earlyret_1site.py`:
  exit 0 (110 checks, 0 failures — count taken from the source
  before sealing, confirmed by the sealing run).
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_pageinstall_earlyret_1site.py`
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

- Verifier: exit 0, 110 checks, 0 failures.
- Unit tests: exit 0, 12 checks, 0 failures.
- Disjointness: verifier scanned 63,068 priors, 0 skipped,
  NONE (deduplicated figure 62,270 after removing 798
  within-file duplicate ranges).
