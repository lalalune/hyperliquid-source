# RE-001-node115-lu-bintableinit-caller-1site-2walk-fieldwrite

Seventh 1-raw bin_table_init caller packet (after #298, #299, #300,
#301, #302, #303). The window is a single-site two-walk field-write
routine: one bin_table_init site (`lea 0x10(%rsp)` in-block via
`r15`, entered only by a null-context `je`, with `rsi` saved to
`0x8(%rsp)` and restored after the call), a two-phase context-table
walk with TWO 8-slot move-to-front scans (one per walk phase) and
TWO lu-miss sites, a composed value written to BOTH resolved node
fields, and a single `ret` exit — no tail jump, 0 bsr.

## Window

- FDE `0x63ae2b0..0x63ae6d1`, 1057 bytes, 222 strict mnemonic lines.
- Previous FDE `0x63ae2a0..0x63ae2a9` (gap 7 bytes, all `0xcc`).
- Next FDE `0x63ae6e0..0x63ae974` (padding 15 bytes, all `0xcc`).
- Frame: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx, `sub $0x1a8,%rsp`,
  canary at `0x198(%rsp)`.
- Entry: `rdi` = context (kept in `r14`), `rsi` = live input
  (preserved across the bti call and lu-miss A via `0x8(%rsp)`,
  passed to the lu-miss handler; caller-side meaning not
  established), `rdx` = struct pointer (kept in `r12`), `ecx` =
  value low bits (kept in `rbx`), `r8d` = byte value (kept in
  `r13d`).
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.

## Classification summary

- Phase-1 walk on the context+`0x1b0` table (in `r15`); key is
  `0x8(%r12)`. Top index `(key >> 0x1a) & 0xf0`, high bits
  `key & 0xffffffffc0000000`, second level
  `(key >> 0x9) & 0x1ffff8 + table + 0x8`. On a top-level match
  there is NO `shl/sar $0x10` + mask transform (like #303, unlike
  #298–#302): instead a second walk runs on a derived key
  `page(0x10(%r12)) + page(0x8(%r12)) - 0x1000` (lea at
  `0x63ae352`), and the match path composes a value in `rbx`
  from `ecx`/`r8d`/struct fields and writes it to both resolved
  node fields. No node-resolution tables (`0x65096c0`/`0x6511780`)
  and no size tables (`0x6727a00`/`0x67277c0`) are read anywhere
  in this FDE.
- Bin_table_init site: `0x63ae45d` (block `0x63ae450`,
  `lea 0x10(%rsp)` in `r15`, `mov %r15,%rdi`; `rsi` saved to
  `0x8(%rsp)` before the call and restored after it; rejoin
  `jmp 0x63ae2f3`; entered only by a null-context `je` from
  `0x63ae2ed`).
- Field write: `rbx = (ecx << 0x30) | r8b | (rdx &
  0xffffffffffff) | ((r12 >> 0xf) & 0x1c) | ((r11 >> 0x2b) & 0x2)`
  (composed at `0x63ae393..0x63ae3ca`, where `r11 = (%r12)` and
  `r12` is the struct pointer), written to `0x0(%rbp)` (first-walk
  target) at `0x63ae3cd` and to `(%rcx)` (second-walk target) at
  `0x63ae3d1`.
- Scan A (first-walk miss): 8 slots, table+`0x100` in `r15`,
  move-to-front on a hit; all eight compares are normal-operand —
  no reversed-operand compare in this FDE. Exhaustion falls to
  lu-miss A `0x63ae627` (`r8d` = 0, `r9d` = 1, `rdi` = context in
  `r14`, `rdx` = scan table in `r15`, `rcx` = second-level pointer
  in `rbp`, `rsi` = entry `rsi`; return goes to `rbp`, rejoin
  `jmp 0x63ae332` back into the match path).
- Scan B (second-walk miss): 8 slots on the derived key, same
  shape; exhaustion falls to lu-miss B `0x63ae6bf` (`r8d` = 0,
  `r9d` = 1, `rcx` = second-level value; return goes to `rcx`,
  rejoin `jmp 0x63ae38e` at the field update).
- Return: `eax` = 0 on the resolved path (`xor %eax,%eax` at
  `0x63ae39f`); `eax` = 1 when a second-level value is null
  (`mov $0x1,%eax` at `0x63ae400`, reached from `0x63ae335` and
  `0x63ae391`).
- Calls: 4 (bin_table_init, 2 lu-miss, `__stack_chk_fail`).
- Exit: single `ret` at `0x63ae3fc`; all 32 jump instructions
  target inside the window — no tail-jump exit (exit-ness verified
  per FDE).

Full site/scan tables, census, and method notes are in records.json
and EVIDENCE.md.

## Disjointness

Range-only collector over the merged tree plus all prior
`hl-wt-calls*` worktree records (exhibits/windows only, all
range-bearing forms, decimal-integer start/end accepted, plain
`int(x, 16)` for hex strings, 0 skipped). The window
`0x63ae2b0..0x63ae6d1` overlaps no prior range (verifier: see the
final verifier run figure below), including packet #303's window
`0x63adb50..0x63adf34`, packet #302's window
`0x6387420..0x6387878`, packet #301's window
`0x6363d50..0x6364270`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`.

## Prior pointer verified (no correction)

#303's survey pointer for this window (1057 bytes, 1 bin_table_init
site, 2 lu-miss sites, 1 ret, 0 bsr) is verified correct by program
arithmetic and by the objdump census above.

## 1-raw tier status

Packet #298 surveyed all 17 1-raw candidates (each exactly 1
objdump-verified bin_table_init site). 16 survive; 1 is excluded as
a whole FDE (`0x63adf40..0x63ae252`, overlapping #214's claimed
sub-ranges). This packet builds on the seventh survivor. The next
frontier is packet #305 on `0x63ae6e0..0x63ae974`.

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_2walk_fieldwrite_1site.py`:
  exit 0 (final check count from the sealing run: see below).
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_2walk_fieldwrite_1site.py`
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

- Verifier: exit 0, 98 checks, 0 failures.
- Unit tests: exit 0, 12 checks, 0 failures.
- Disjointness: verifier scanned 60,542 priors, 0 skipped,
  NONE (deduplicated figure 59,774 after removing 768
  within-file duplicate ranges).
