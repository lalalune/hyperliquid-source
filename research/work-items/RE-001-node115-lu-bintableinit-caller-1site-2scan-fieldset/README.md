# RE-001-node115-lu-bintableinit-caller-1site-2scan-fieldset

Sixth 1-raw bin_table_init caller packet (after #298, #299, #300,
#301, #302). The window is a single-site field-set routine: one
bin_table_init site (plain `%rsp` in-block via `r15`, entered only
by a null-context `je` — the first plain-rsp site in the 1-raw
chain), a two-phase context-table walk with TWO 8-slot
move-to-front scans (one per walk phase) and TWO lu-miss sites, a
3-bit field update (value in `ecx`, written to `*rbx` bits 17-19
at entry and to the resolved node field bits 2-4 at exit, plus a
second node field when the second walk resolves one), and a single
`ret` exit — no tail jump, 0 bsr.

## Window

- FDE `0x63adb50..0x63adf34`, 996 bytes, 209 strict mnemonic lines.
- Previous FDE `0x63adb40..0x63adb4c` (gap 4 bytes, all `0xcc`).
- Next FDE `0x63adf40..0x63ae252` (padding 12 bytes, all `0xcc`) —
  the excluded whole FDE (overlaps #214's claimed sub-ranges),
  not decoded here.
- Frame: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx, `sub $0x198,%rsp`,
  canary at `0x188(%rsp)`.
- Entry: `rdi` = context (kept in `rbp`), `rsi` = key (kept in
  `r13`), `rdx` = struct pointer (kept in `rbx`), `ecx` = 3-bit
  field value (kept in `r12`, shifted `<< 0x11` for the `*rbx`
  write and `* 4` for the node-field write).
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.

## Classification summary

- Entry field write: `*rbx` bits 17-19 are replaced by `ecx << 0x11`
  (`and $0xfffffffffff1ffff` then `or %rdx`) before the
  null-context test.
- Phase-1 walk on the context+`0x1b0` table (in `r15`); key is
  `0x8(%rbx)`. Top index `(key >> 0x1a) & 0xf0`, high bits
  `key & 0xffffffffc0000000`, second level
  `(key >> 0x9) & 0x1ffff8 + table + 0x8`. On a top-level match
  there is NO `shl/sar $0x10` + mask transform (unlike
  #298–#302): instead the page check
  `(0x10(%rbx) & ~0xfff) == 0x1000` selects a direct field-update
  arm, and otherwise a second walk runs on a derived key
  `page(0x10(%rbx)) + page(0x8(%rbx)) - 0x1000`. No
  node-resolution tables (`0x65096c0`/`0x6511780`) and no size
  tables (`0x6727a00`/`0x67277c0`) are read anywhere in this FDE.
- Bin_table_init site: `0x63adce6` (block `0x63adce0`, plain `%rsp`
  in `r15`, `mov %r15,%rdi`; no save/restore — `r15` itself
  becomes the stack-temp table and the walk restarts at
  `0x63adba7` using it; rejoin `jmp 0x63adba7`).
- Field update: node field `(%r14)` has bits 2-4 cleared
  (`and $0xffffffffffffffe3`) and ORed with `ecx * 4`; a second
  target `(%rdx)` gets the same value when the second walk
  resolves one (`test %rdx,%rdx`).
- Scan A (first-walk miss): 8 slots, table+`0x100` in `r15`,
  move-to-front on a hit; all eight compares are normal-operand —
  no reversed-operand compare in this FDE. Exhaustion falls to
  lu-miss A `0x63ade8d` (`r8d` = 1, `r9d` = 0, `rdi` = context in
  `rbp`, `rdx` = scan table in `r15`, `rcx` = second-level pointer
  in `r14`, `rsi` = key in `r13`; return goes to `r14`, rejoin
  `jmp 0x63adbe8` back into the match path).
- Scan B (second-walk miss): 8 slots on the derived key, same
  shape; exhaustion falls to lu-miss B `0x63adf22` (`r8d` = 1,
  `r9d` = 0, `rcx` = derived key in `rdx`; return goes to `rdx`,
  rejoin `jmp 0x63adc4e` at the field update).
- Return: no return register is set on the `ret` path; the
  observable effects are the `*rbx` field write at entry and the
  node-field writes at exit.
- Calls: 4 (bin_table_init, 2 lu-miss, `__stack_chk_fail`).
- Exit: single `ret` at `0x63adc8b`; all 32 jump instructions
  target inside the window — no tail-jump exit (exit-ness verified
  per FDE).

Full site/scan tables, census, and method notes are in records.json
and EVIDENCE.md.

## Disjointness

Range-only collector over the merged tree plus all prior
`hl-wt-calls*` worktree records (exhibits/windows only, all
range-bearing forms, decimal-integer start/end accepted, plain
`int(x, 16)` for hex strings, 0 skipped). The window
`0x63adb50..0x63adf34` overlaps no prior range (verifier: see the
final verifier run figure below), including packet #302's window
`0x6387420..0x6387878`, packet #301's window
`0x6363d50..0x6364270`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`.

## Prior pointer verified (no correction)

#302's survey pointer for this window (996 bytes, 1 bin_table_init
site, 2 lu-miss sites, 1 ret, 0 bsr) is verified correct by program
arithmetic and by the objdump census above.

## 1-raw tier status

Packet #298 surveyed all 17 1-raw candidates (each exactly 1
objdump-verified bin_table_init site). 16 survive; 1 is excluded as
a whole FDE (`0x63adf40..0x63ae252`, overlapping #214's claimed
sub-ranges). This packet builds on the sixth survivor. The next
frontier is packet #304 on `0x63ae2b0..0x63ae6d1`.

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_2scan_fieldset_1site.py`:
  exit 0 (final check count from the sealing run: see below).
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_2scan_fieldset_1site.py`
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

- Verifier: exit 0, 92 checks, 0 failures.
- Unit tests: exit 0, 12 checks, 0 failures.
- Disjointness: verifier scanned 59,700 priors, 0 skipped,
  NONE (deduplicated figure 58,942 after removing 758
  within-file duplicate ranges).
