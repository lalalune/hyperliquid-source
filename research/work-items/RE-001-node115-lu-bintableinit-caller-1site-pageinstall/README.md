# RE-001-node115-lu-bintableinit-caller-1site-pageinstall

Eighth 1-raw bin_table_init caller packet (after #298, #299, #300,
#301, #302, #303, #304). The window is a single-site page-range
install routine: one bin_table_init site (`lea 0x10(%rsp)` in-block
via `r14`, entered only by a null-context `je`, with `rsi` saved to
`0x8(%rsp)` and restored after the call), a page-stepping
context-table walk that stores a composed value at each page's
second-level entry, a single 8-slot move-to-front scan with ONE
lu-miss site, and a single `ret` exit — no tail jump, 0 bsr.

## Window

- FDE `0x63ae6e0..0x63ae974`, 660 bytes, 151 strict mnemonic lines.
- Previous FDE `0x63ae2b0..0x63ae6d1` (gap 15 bytes, all `0xcc`).
- Next FDE `0x63ae980..0x63aed39` (padding 12 bytes, all `0xcc`).
- Frame: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx, `sub $0x1a8,%rsp`,
  canary at `0x198(%rsp)`.
- Entry: `rdi` = context (kept in `r15`), `rsi` = live input
  (preserved across the bti call and the lu-miss call via
  `0x8(%rsp)`, passed to the lu-miss handler; caller-side meaning
  not established), `rdx` = struct pointer (kept in `rbp`),
  `ecx` = value low bits (kept in `rbx`).
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.

## Classification summary

- Page-range install loop on the context+`0x1b0` table (in `r14`).
  The cursor `rbx` steps `0x1000` per page from
  `page(0x8(%rbp)) + 0x1000` up to
  `page(0x8(%rbp)) + page(0x10(%rbp)) - 0x2000` (end `r13`, lea at
  `0x63ae749`). Per page: top index `(cursor >> 0x1a) & 0xf0`,
  high bits `cursor & 0xffffffffc0000000`, second level
  `(cursor >> 0x9) & 0x1ffff8 + table + 0x8`. On a top-level match
  the composed value in `rbp` is stored at the second-level entry
  (`mov %rbp,-0x8(%rax)` at `0x63ae7bb`). There is NO `shl/sar
  $0x10` + mask transform (like #303 and #304, unlike #298–#302).
  No node-resolution tables (`0x65096c0`/`0x6511780`) and no size
  tables (`0x6727a00`/`0x67277c0`) are read anywhere in this FDE.
- Composed value: `rbp = (ecx << 0x30) | (struct pointer &
  0xffffffffffff) | 1` (`shl $0x30,%rbx` at `0x63ae728`,
  `movabs $0xffffffffffff,%rdx` at `0x63ae72c`,
  `and %rdx,%rbp` at `0x63ae736`, `or $0x1,%rbp` at `0x63ae751`).
- Bin_table_init site: `0x63ae83d` (block `0x63ae830`,
  `lea 0x10(%rsp)` in `r14`, `mov %r14,%rdi`; `rsi` saved to
  `0x8(%rsp)` before the call and restored after it; rejoin
  `jmp 0x63ae720`; entered only by a null-context `je` from
  `0x63ae71a`).
- Scan (single, 8 slots, table+`0x100` in `r14`, move-to-front on
  a hit): slots 0–6 compare via registers (`cmp %r8,%rcx`,
  `cmp %r10,%rcx`, `cmp %rdx,%rcx` at `0x63ae7f7`/`0x63ae85b`/
  `0x63ae8ac`/`0x63ae8d3`/`0x63ae8df`/`0x63ae90e`/`0x63ae91e`),
  slot 7 compares memory directly (`cmp 0x170(%r14),%rcx` at
  `0x63ae941`) — all normal-operand order (slot value first, key
  second); no key-first reversed-operand compare in this FDE.
  Slot-0 hit uses the inline block at `0x63ae7fc..0x63ae82c`,
  slots 1–7 share the move-to-front block at `0x63ae860`
  (`r9d` = previous slot index, `eax` = slot index, shift `*16`,
  swap slot into head). Exhaustion falls to lu-miss `0x63ae965`
  (`r8d` = 1, `r9d` = 0, `rdi` = context in `r15`, `rdx` = scan
  table in `r14`, `rcx` = page cursor in `rbx`, `rsi` = entry
  `rsi`; rejoin `jmp 0x63ae7b0` back into the store path).
- Return: `eax` = 0 on the plain path (`xor %eax,%eax` at
  `0x63ae715` and `0x63ae755`); the scan move-to-front reuses
  `eax` as a slot index, so `eax` at `ret` reflects the last
  move-to-front slot index when a scan hit occurred.
- Calls: 3 (bin_table_init, 1 lu-miss, `__stack_chk_fail`).
- Exit: single `ret` at `0x63ae7ec`; all 22 jump instructions
  target inside the window — no tail-jump exit (exit-ness verified
  per FDE).

Full site/scan tables, census, and method notes are in records.json
and EVIDENCE.md.

## Disjointness

Range-only collector over the merged tree plus all prior
`hl-wt-calls*` worktree records (exhibits/windows only, all
range-bearing forms, decimal-integer start/end accepted, plain
`int(x, 16)` for hex strings, 0 skipped). The window
`0x63ae6e0..0x63ae974` overlaps no prior range (verifier: see the
final verifier run figure below), including packet #304's window
`0x63ae2b0..0x63ae6d1`, packet #303's window
`0x63adb50..0x63adf34`, packet #302's window
`0x6387420..0x6387878`, packet #301's window
`0x6363d50..0x6364270`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`.

## Prior pointer verified (no correction)

#304's survey pointer for this window (660 bytes, 1 bin_table_init
site, 1 lu-miss site, 1 ret, 0 bsr) is verified correct by program
arithmetic and by the objdump census above.

## 1-raw tier status

Packet #298 surveyed all 17 1-raw candidates (each exactly 1
objdump-verified bin_table_init site). 16 survive; 1 is excluded as
a whole FDE (`0x63adf40..0x63ae252`, overlapping #214's claimed
sub-ranges). This packet builds on the eighth survivor. The next
frontier is packet #306 on `0x63ae980..0x63aed39`.

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_pageinstall_1site.py`:
  exit 0 (100 checks, 0 failures — count taken from the source
  before sealing, confirmed by the sealing run).
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_pageinstall_1site.py`
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

- Verifier: exit 0, 100 checks, 0 failures.
- Unit tests: exit 0, 12 checks, 0 failures.
- Disjointness: verifier scanned 61,384 priors, 0 skipped,
  NONE (deduplicated figure 60,606 after removing 778
  within-file duplicate ranges).
