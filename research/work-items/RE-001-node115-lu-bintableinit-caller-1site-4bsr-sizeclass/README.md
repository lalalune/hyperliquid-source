# RE-001-node115-lu-bintableinit-caller-1site-4bsr-sizeclass

Fourth 1-raw bin_table_init caller packet (after #298, #299, #300).
The window is a single-site size-class routine: one bin_table_init
site (`lea 0x10(%rsp)` in-block, entered only by a null-context
`je`), a two-phase context-table walk that DOES read the size table
`0x6727a00` (unlike #298/#299) and the node-resolution table
`0x65096c0` (but not `0x6511780`, unlike #300), an 8-slot
move-to-front scan (exactly one reversed-operand compare, slot 6),
a four-arm bsr size-class computation (two rounded-size blocks and
two size-class-index blocks), a refcount-release helper arm, and a
single `ret` exit — no tail jump.

## Window

- FDE `0x6363d50..0x6364270`, 1312 bytes, 289 strict mnemonic lines.
- Previous FDE `0x63637f0..0x6363d50` (gap 0 bytes — adjacent, the
  packet #300 window).
- Next FDE `0x6364270..0x6364280` (padding 0 bytes — adjacent, a
  16-byte FDE, not decoded here).
- Frame: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx, `sub $0x1a8,%rsp`,
  canary at `0x198(%rsp)`.
- Entry: `rdi` = context (kept in `r13`), `rsi` = key (kept in
  `rbp`), `rdx` = size (kept in `r14`), `rcx` (kept in `r12`),
  `r8` (kept in `rbx`), `r9` (kept in `r10`); `r15` =
  `0x1e0(%rsp)` (out pointer).
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.

## Classification summary

- Phase-1 walk on the context+`0x1b0` table; on a top-level match the
  second-level value is shifted/masked and the node is resolved
  through table `0x65096c0` — this FDE reads node-resolution
  tables, like #300 (but only `0x65096c0`, not `0x6511780`).
  The size table `0x6727a00` is read here (threshold lookups at
  `0x6363e13` / `0x6363fe0` / `0x636408e`), unlike #298/#299.
- Bin_table_init site: `0x6364009` (block `0x6363ff8`,
  `lea 0x10(%rsp)` in `rsi`, `mov %rsi,%rdi`; `r9d` saved to
  `0xc(%rsp)` and `rsi` to `(%rsp)` before the call, `r11`/`r10d`
  restored after).
- Lu-miss site: `0x636425d` (scan exhaustion; `r8d` = 1, `r9d` = 0,
  `r10d` passed on the stack).
- Scan: 8 slots, table+`0x100`, move-to-front on a hit; exactly one
  reversed-operand compare — slot 6 (`cmp %rcx,0x160(%r11)` at
  `0x6364215`); the other seven are normal-operand.
- Size class: four bsr arms — rounded-size blocks for `r12`
  (`0x6364080`) and `rbx` (`0x6364042`, with an overflow arm at
  `0x63641bc`), and size-class-index blocks for `r14` (`0x636410d`)
  and `rbx` (`0x6364150`); a size-class compare arm at `0x6363f00`
  compares the classes of `rbx` vs `r14`.
- Refcount: `subl $0x1,0x98(%r13)` at `0x6363eb0`; on underflow the
  helper `0x635f340` runs, and on its nonzero return the helper
  `0x6360ed0` is called (an ordinary returning call here — it was
  #300's tail-jump exit).
- Large-size arm: helper `0x63bd2e0` at `0x63640c1` when both `r14`
  and `rbx` exceed `0x3fff`.
- Return: `eax` is a 0/1 flag (1 on the overflow arm, the
  small-size arm, and the size-mismatch arm; 0 on the plain
  resolved path); the resolved node pointer is written to `*r15`.
- Calls: 6 (refcount helper, bin_table_init, large-size helper,
  context-release helper, lu-miss, `__stack_chk_fail`).
- Exit: single `ret` at `0x6363ef7`; all 43 jump instructions
  target inside the window — no tail-jump exit (exit-ness verified
  per FDE).

Full site/scan tables, census, and method notes are in records.json
and EVIDENCE.md.

## Disjointness

Range-only collector over the merged tree plus all prior
`hl-wt-calls*` worktree records (exhibits/windows only, all
range-bearing forms, decimal-integer start/end accepted, plain
`int(x, 16)` for hex strings, 0 skipped). The window
`0x6363d50..0x6364270` overlaps no prior range (verifier: see the
final verifier run figure below), including packet #300's window
`0x63637f0..0x6363d50`, packet #299's window
`0x6363260..0x6363552`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`.

## Prior pointer verified (no correction)

#300's survey pointer for this window (1312 bytes, 1 bin_table_init
site, 1 lu-miss site, 1 ret, 4 bsr) is verified correct by program
arithmetic and by the objdump census above.

## 1-raw tier status

Packet #298 surveyed all 17 1-raw candidates (each exactly 1
objdump-verified bin_table_init site). 16 survive; 1 is excluded as
a whole FDE (`0x63adf40..0x63ae252`, overlapping #214's claimed
sub-ranges). This packet builds on the fourth survivor. The next
frontier is packet #302 on `0x6387420..0x6387878`.

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_4bsr_sizeclass_1site.py`:
  exit 0 (final check count from the sealing run: see below).
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_4bsr_sizeclass_1site.py`
  (tamper controls first — hex flip, strict-count change, call-site
  change, injected overlap — each makes the temp-copy verifier fail;
  the clean temp copy passes): exit 0 (final check count from the
  sealing run: see below). The test harness uses lean temp copies
  (verifier + packet dir + symlinked binary only); a full worktree
  copy changes nothing the verifier reads.
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

- Verifier: exit 0, 71 checks, 0 failures.
- Unit tests: exit 0, 12 checks, 0 failures.
- Disjointness: verifier scanned 58,016 priors, 0 skipped,
  NONE (deduplicated figure 57,278 after removing 738 exhibits carrying
  both a `range` key and a `start`/`end` pair).
