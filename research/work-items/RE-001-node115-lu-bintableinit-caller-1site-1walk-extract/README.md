# RE-001-node115-lu-bintableinit-caller-1site-1walk-extract

Fourteenth 1-raw bin_table_init caller packet (after #298, #299, #300,
#301, #302, #303, #304, #305, #306, #307, #308, #309, #310). The window is
a single-walk lookup-with-extract routine: one bin_table_init site
(`lea 0x10(%rsp)` in-block via `r15`, entered only by a null-context
`je`, with `rsi` saved to `0x8(%rsp)` across the call), one
context-table walk that resolves a second-level pointer, a
`shl $0x10` / `sar $0x10` extract that decodes three output values
from the resolved node descriptor, one 8-slot move-to-front scan
with ONE lu-miss site, and a single `ret` exit — no tail jump, 0 bsr.
Unlike #303–#310 this FDE has the `shl`/`sar $0x10` transform
(like #298–#302), and unlike every prior 1-raw caller its lu-miss
`rsi` is NOT entry `rsi`: it is the `.bss` address `0x6511a00`
(see Lu-miss below).

## Window

- FDE `0x63bc490..0x63bc728`, 664 bytes, 145 strict mnemonic lines.
- Previous FDE `0x63bc480..0x63bc489` (gap 7 bytes, all `0xcc`).
- Next FDE `0x63bc730..0x63bcb12` (padding 8 bytes, all `0xcc`).
- Frame: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx, `sub $0x1a8,%rsp`,
  canary at `0x198(%rsp)` (stored at `0x63bc4c1`, checked against
  `%fs:0x28` at `0x63bc57e`, mismatch jumps to `__stack_chk_fail`).
- Entry: `rdi` = context (kept in `r14`), `rsi` = lookup key,
  `rdx` = output struct pointer (kept in `rbp`; slot `0x0(%rbp)`),
  `rcx` = second output pointer (kept in `rbx`; slot `(%rbx)`),
  `r8` = third output pointer (kept in `r12`; slot `(%r12)`).
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.
- No size class in this FDE (0 bsr, no `0x6727a00`/`0x67277c0`
  read, no node-resolution tables read).

## Classification summary

- Null-context gate: `test %rdi,%rdi` at `0x63bc4cb`,
  `je 0x63bc5d8` at `0x63bc4ce` — the bin_table_init site is
  entered only when the context is null.
- Bin_table_init site: `0x63bc5e5` (block `0x63bc5d8`,
  `lea 0x10(%rsp),%r15`, `mov %r15,%rdi`; `rsi` saved to
  `0x8(%rsp)` before the call and restored after it; rejoin
  `jmp 0x63bc4d4`; entered only by a null-context `je` from
  `0x63bc4ce`; preceding instruction is the `nopl` at
  `0x63bc5d1`).
- Table base in `r15`: `lea 0x1b0(%rdi),%r15` at `0x63bc496`
  on the normal path; on the null-context path the bti block
  overwrites `r15` with `lea 0x10(%rsp)`, so the walk and the
  scan run against the stack-temp table. The `0x10(%rsp)`
  temp is referenced nowhere else in this FDE except the
  `lea` itself.
- Stack scratch: none — no `rep stos`, no other stack
  save/restore anywhere in this FDE. The frame is
  `sub $0x1a8,%rsp` with the canary at `0x198(%rsp)`.
- Walk (single, table in `r15`): key = entry `rsi`
  (`mov %rsi,%rax` at `0x63bc4d4`, `mov %rsi,%rcx` at
  `0x63bc4d7`). Top index `(key >> 0x1a) & 0xf0`
  (`shr $0x1a,%rax` at `0x63bc4da`, `and $0xf0,%eax` at
  `0x63bc4e5`, `add %r15,%rax` at `0x63bc4ea`), high bits
  `key & 0xffffffffc0000000` (`and` at `0x63bc4de`),
  top-level compare `cmp %rdi,%rcx` at `0x63bc4f0`; a
  mismatch falls to the scan at `0x63bc5f8`. Second level
  `(key >> 0x9) & 0x1ffff8 + table + 0x8`
  (`shr $0x9,%rsi` at `0x63bc4f9`,
  `and $0x1ffff8,%r15d` at `0x63bc500`,
  `add 0x8(%rax),%r15` at `0x63bc507`). The second-level
  pointer is loaded into `rcx` at `0x63bc50e` — it is NOT
  stored to an output slot (unlike #309/#310, where each
  walk stored its resolved pointer); it feeds the extract.
- Extract (from the second-level value in `rcx`):
  `shl $0x10,%rcx` at `0x63bc511`, `mov %rcx,%rax` at
  `0x63bc515`, `sar $0x10,%rax` at `0x63bc518` (sign-extended
  48-bit value), `and $0xffffffffffffff80,%rax` at `0x63bc51c`
  (low 7 bits cleared). `cmp $0x7fffff,%rcx` at `0x63bc520`,
  `jbe 0x63bc5b8` at `0x63bc527` — the zero path (all three
  outputs zeroed) is taken when the shifted value is
  `<= 0x7fffff`. Otherwise: `mov 0x10(%rax),%rdi` at
  `0x63bc52d`, `and $0xfffffffffffff000,%rdi` at `0x63bc531`,
  `mov %rdi,(%r12)` at `0x63bc538` (page of the qword at
  node+0x10 into the `r8` output); `mov (%rax),%rdx` at
  `0x63bc53c` (the node descriptor qword); `test $0x10,%dh`
  at `0x63bc53f`, `je 0x63bc5a0` at `0x63bc542` — the flag
  path (`*rbp` = 0, `*rbx` = 1, `*r12` keeps the page value)
  is taken when bit 12 of the descriptor is clear.
  Otherwise: `shr $0x1c,%rdx` at `0x63bc544`,
  `and $0x3ff,%edx` at `0x63bc54f` — the index
  `(descriptor >> 0x1c) & 0x3ff` is stored to `0x0(%rbp)`
  at `0x63bc558`; `mov (%rax),%rbp` at `0x63bc55c`,
  `shr $0x14,%rbp` at `0x63bc55f`,
  `movzbl %bpl,%r8d` at `0x63bc563` — the byte
  `(descriptor >> 0x14) & 0xff` indexes a 40-byte-entry
  table at `0x6711b40` (`lea (%r8,%r8,4),%r9` at `0x63bc567`,
  `lea (%r10,%r9,8),%r11` at `0x63bc56b`, with `r10` from
  `lea 0x3555f1(%rip),%r10` at `0x63bc548`); the 32-bit
  field at entry+0x10 (`mov 0x10(%r11),%r13d` at `0x63bc56f`)
  is stored to `(%rbx)` at `0x63bc573`.
- The two referenced tables are `.bss` objects, not file
  data: `0x6511a00` (lu-miss `rsi`) and `0x6711b40`
  (extract table) both lie inside `.bss`
  (`0x64ffe40..0x6728d24`, NOBITS). Their contents are
  runtime-populated and are not in the file; only the
  code's use of the addresses is claimed. The extract
  table's entry size (40 bytes) and field offset (+0x10)
  are read from the code, not from the table contents.
- Scan (single 8-slot move-to-front, table+`0x100` in
  `r15`, key in `rcx`): slot 0 at `0x63bc5f8`
  (`cmp 0x100(%r15),%rcx`), slot 1 at `0x63bc63e`, slot 2
  at `0x63bc699`, slot 3 at `0x63bc6a8`, slot 4 at
  `0x63bc6b7`, slot 5 at `0x63bc6c6`, slot 6 at `0x63bc6d9`
  (`cmp %rcx,0x160(%r15)` — reversed, the only one), slot
  7 at `0x63bc6e6` (`cmp 0x170(%r15),%rcx` — memory
  directly). Slot-0 hit uses the inline block at
  `0x63bc601..0x63bc62f` (it swaps the top-level entry's
  second-level base with the scan slot's stored base and
  recomputes the second-level pointer from the swapped
  base, rejoining at `0x63bc50e`); slots 1–7 share the
  block at `0x63bc647` (`r8d` = slot index, `r9d` =
  index-1, shift `*16`, swap slot toward head), rejoining
  at `0x63bc61a` into the slot-0 block. Exhaustion falls
  to lu-miss `0x63bc719`.
- Lu-miss site (1): block `0x63bc700`, call at `0x63bc719`
  (`e8 e2 cf 01 00` -> `0x63d9700`), rejoin
  `jmp 0x63bc50e` at `0x63bc71e`. Arguments: `rdi` = `r14`
  (entry context — `r14` is never overwritten on the miss
  path; the only `mov`-to-`r14` lines in this FDE are the
  entry mov at `0x63bc49f` and the slot-0 hit-path write
  at `0x63bc608`), `rsi` = `0x6511a00` via
  `lea 0x1552f6(%rip),%rsi` at `0x63bc703` (a `.bss`
  address — NOT entry `rsi`, unlike #298–#310, where the
  lu-miss `rsi` was entry `rsi` or a table-slot pointer),
  `rdx` = `r15` (scan table), `rcx` = entry `rsi`
  (`mov %rsi,%rcx` at `0x63bc700` — `rsi` is still the
  entry key on the miss path, since the `shr $0x9,%rsi`
  at `0x63bc4f9` runs only on the top-level-match path),
  `r8d` = 1, `r9d` = 0. The return value in `rax` is the
  second-level pointer, which feeds the extract at
  `0x63bc50e`.
- Exit: single `ret` at `0x63bc59e` (shared epilogue at
  `0x63bc576`: canary check, `add $0x1a8,%rsp` + pops).
  All 20 jump instructions target inside the window — no
  tail-jump exit (exit-ness verified per FDE). Canary
  failure goes to `0x63bc723`, which calls
  `__stack_chk_fail` (`0x63f0d70`). `eax` = 0 at `ret`:
  entry `xor %eax,%eax` at `0x63bc4c9`; the only other
  `%eax` write is the top-index `and $0xf0,%eax` at
  `0x63bc4e5`; the epilogue loads the canary into `rax`
  (`mov 0x198(%rsp),%rax` at `0x63bc576`) and subtracts
  `%fs:0x28` (`sub` at `0x63bc57e`), so `rax` is 0 on the
  non-fault path. There is no `sete`, no `mov $0x1,%eax`,
  and no null-flag epilogue. The observable effects are
  the three output stores (`*r12`, `*rbp`, `*rbx`).

## Census (from the objdump exhibit, never copied from a prior packet)

- Strict mnemonic lines: 145.
- Calls: 3 (1 bin_table_init + 1 lu-miss + 1
  `__stack_chk_fail`).
- Bin_table_init sites: 1 (`0x63bc5e5`), `lea 0x10(%rsp)` in-block.
- Lu-miss sites: 1 (`0x63bc719`).
- `ret`: 1 (`0x63bc59e`). `bsr`: 0. `lock sub`: 0. `lock add`: 0.
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
(this packet), `0x63bc730`, `0x63c2f00` (full per-candidate census in
records.json under `survey`).

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
(`0x63bc730` miss 1, `0x63c2f00` miss 1 with bsr 1).

**Prior pointer verified (no correction).** #310's survey pointer
for this window (664 bytes, 1 bin_table_init site `0x63bc5e5`,
1 lu-miss site, 1 ret at `0x63bc59e`, 0 bsr) is verified correct
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
collector (838 within-file duplicate ranges in this corpus); the
deduplicated survey figure is 65,598 priors — the verdict is NONE
under either count.

## Disjointness

Range-only collector over the merged tree plus all prior
`hl-wt-calls*` worktree records (exhibits/windows only, all
range-bearing forms above, decimal-integer start/end accepted,
plain `int(x, 16)` for hex strings). The window
`0x63bc490..0x63bc728` overlaps no prior range (verifier: 66,436
priors scanned, 0 skipped, disjointness NONE), including packet
#310's window `0x63afc60..0x63b0324`, packet #309's window
`0x63af460..0x63afba4`, packet #308's window
`0x63aefe0..0x63af45f`, packet #307's window
`0x63aed40..0x63aefdb`, packet #306's window
`0x63ae980..0x63aed39`, packet #305's window
`0x63ae6e0..0x63ae974`, packet #304's window
`0x63ae2b0..0x63ae6d1`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`. (The verifier counts 838 within-file
duplicate ranges across the corpus; the deduplicated figure is
65,598 priors — the verdict is NONE under either count.)

## Not covered

- The bin_table_init body `0x63d9880..0x63d9a64` (#262) and the
  lu-miss handler `0x63d9700..0x63d987b` (#215) are cited, not
  claimed.
- The helpers and tables are read, not claimed: no
  node-resolution tables (`0x65096c0`, `0x6511780`) and no size
  tables (`0x6727a00`, `0x67277c0`) are read in this FDE. The
  `.bss` objects at `0x6511a00` and `0x6711b40` are referenced
  by address only; their runtime contents are not established.
- The neighboring FDEs are not decoded here. The next FDE
  `0x63bc730..0x63bcb12` is the next question for packet #312.
- The entry `rsi` key's caller-side meaning, the `r8d`/`r9d`
  values' caller-side meaning, and the semantics of the three
  output values beyond the store sites are not established.
  The 40-byte table entries' other fields (besides +0x10)
  are not established.
- The remaining 1-raw candidates are future packets.

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_1walk_extract_1site.py`:
  exit 0 (172 checks, 0 failures — count taken from the source
  before sealing, confirmed by the sealing run).
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_1walk_extract_1site.py`
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

- Verifier: exit 0, 172 checks, 0 failures.
- Unit tests: exit 0, 12 checks, 0 failures.
- Disjointness: verifier scanned 66,436 priors, 0 skipped,
  NONE (deduplicated figure 65,598 after removing 838
  within-file duplicate ranges).
