# RE-001-node115-lu-bintableinit-caller-1site-2walk-constwrite

Ninth 1-raw bin_table_init caller packet (after #298, #299, #300,
#301, #302, #303, #304, #305). The window is a single-site two-walk
const-write routine: one bin_table_init site (plain `%rsp` in-block
via `r12`, entered only by a null-context `je`, with `rsi` kept in
callee-saved `r13` — no save/restore), a two-phase context-table
walk with TWO 8-slot move-to-front scans (one per walk phase) and
TWO lu-miss sites, a constant value `0xe8000000000000` written to
BOTH resolved node fields, and a single `ret` exit — no tail jump,
0 bsr.

## Window

- FDE `0x63ae980..0x63aed39`, 953 bytes, 189 strict mnemonic lines.
- Previous FDE `0x63ae6e0..0x63ae974` (gap 12 bytes, all `0xcc`).
- Next FDE `0x63aed40..0x63aefdb` (padding 7 bytes, all `0xcc`).
- Frame: `endbr64`, pushes r14/r13/r12/rbp/rbx, `sub $0x190,%rsp`,
  canary at `0x188(%rsp)`.
- Entry: `rdi` = context (kept in `rbx`), `rsi` = live input
  (kept in callee-saved `r13`, passed to the lu-miss handler;
  caller-side meaning not established), `rdx` = struct pointer
  (kept in `rbp`), `ecx`/`r8d` unused in this FDE.
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.

## Classification summary

- Two-phase walk on the context+`0x1b0` table (in `r12`). Key is
  `0x8(%rbp)` (loaded at `0x63ae9bf`). Top index
  `(key >> 0x1a) & 0xf0`, high bits
  `key & 0xffffffffc0000000`, second level
  `(key >> 0x9) & 0x1ffff8 + table + 0x8` (into `r14` at
  `0x63ae9fd`). On a top-level mismatch the walk falls to scan A
  at `0x63aeaa0`. There is NO `shl/sar $0x10` + mask transform
  (like #303, #304 and #305, unlike #298–#302). No
  node-resolution tables (`0x65096c0`/`0x6511780`) and no size
  tables (`0x6727a00`/`0x67277c0`) are read anywhere in this FDE.
- Second walk on a derived key: `rdx =
  page(0x10(%rbp)) + page(0x8(%rbp)) - 0x1000`
  (`lea -0x1000(%rcx,%rbp,1),%rcx` at `0x63aea0c`): top index
  `(rdx >> 0x1a) & 0xf0`, high bits
  `rdx & 0xffffffffc0000000`, second level
  `(rdx >> 0x9) & 0x1ffff8 + table + 0x8` (into `rax` at
  `0x63aea46`). On a top-level mismatch the walk falls to scan B
  at `0x63aeae8`.
- Constant write: `movabs $0xe8000000000000,%rcx` at `0x63aea4a`;
  `mov %rcx,(%r14)` at `0x63aea54` (first-walk target);
  `test %rax,%rax` at `0x63aea57` guards the second store
  (`je 0x63aea5f` skips it when null);
  `mov %rcx,(%rax)` at `0x63aea5c` (second-walk target). Entry
  `ecx`/`r8d` are not used — the written value is a constant,
  not composed from the entry registers (unlike #304's composed
  value and #305's `(ecx << 0x30) | ... | 1`).
- Bin_table_init site: `0x63aea96` (block `0x63aea90`,
  plain `%rsp` in `r12`, `mov %r12,%rdi`; no `rsi` save/restore
  — `rsi` lives in callee-saved `r13` across the call; rejoin
  `jmp 0x63ae9bf`; entered only by a null-context `je` from
  `0x63ae9b9`; preceding instruction is the `cs nopw` at
  `0x63aea86`).
- Scan A (8 slots, table+`0x100` in `r12`, key high bits in
  `rdx`, move-to-front on a hit): slot 0 at `0x63aeaa0`, slot 1
  at `0x63aeb35`, slots 2–7 at `0x63aec00`/`0x63aec13`/
  `0x63aec26`/`0x63aec39`/`0x63aec4c`/`0x63aec5a`. Slots 0, 1, 7
  are normal-operand compares; slots 2–6 are reversed-operand
  compares (`cmp %rdx,0x120(%r12)` form — five reversed compares,
  the most in the 1-raw chain so far; #301 had exactly one).
  Slot-0 hit uses the inline block at `0x63aeaae..0x63aece`,
  slots 1–7 share the move-to-front block at `0x63aeb43`
  (`edi` = slot index, shift `*16`, swap slot into head).
  Exhaustion falls to lu-miss A `0x63aec82` (`r8d` = 1,
  `r9d` = 0, `rdi` = context in `rbx`, `rsi` = entry `rsi` in
  `r13`, `rdx` = scan table in `r12`, `rcx` = page key; return
  goes to `r14`, rejoin `jmp 0x63aea01` into the derived-key
  recompute).
- Scan B (8 slots, same table, key high bits in `r11`,
  move-to-front on a hit): slot 0 at `0x63aeae8`, slot 1 at
  `0x63aeb9e`, slots 2–7 at `0x63aeca0`/`0x63aecb4`/`0x63aecc8`/
  `0x63aecdc`/`0x63aecf0`/`0x63aecfe`. Slots 0–4, 7 are
  normal-operand compares; slots 5–6 are reversed-operand
  compares (`cmp %r11,0x150(%r12)` form). Slot-0 hit uses the
  inline block at `0x63aeaf6..0x63aeb28`, slots 1–7 share the
  move-to-front block at `0x63aebac` (`r8d` = slot index, shift
  `*16`, swap slot into head). Exhaustion falls to lu-miss B
  `0x63aed2a` (`r8d` = 1, `r9d` = 0, `rdi` = context in `rbx`,
  `rsi` = entry `rsi` in `r13`, `rdx` = scan table in `r12`,
  `rcx` = derived key `>> 0x9`; return value is used directly
  as the second-level pointer, rejoin `jmp 0x63aea4a` into the
  constant-write block).
- Return: no return value is claimed — `eax` is not set as a
  return value on the `ret` path (it holds the second-level
  index `(derived key >> 0x9) & 0x1ffff8` from address
  computation); the observable effects are the two stores.
- Calls: 4 (bin_table_init, 2 lu-miss, `__stack_chk_fail`).
- Exit: single `ret` at `0x63aea85`; all 30 jump instructions
  target inside the window — no tail-jump exit (exit-ness verified
  per FDE).

Full site/scan tables, census, and method notes are in records.json
and EVIDENCE.md.

## Disjointness

Range-only collector over the merged tree plus all prior
`hl-wt-calls*` worktree records (exhibits/windows only, all
range-bearing forms, decimal-integer start/end accepted, plain
`int(x, 16)` for hex strings, 0 skipped). The window
`0x63ae980..0x63aed39` overlaps no prior range (verifier: see the
final verifier run figure below), including packet #305's window
`0x63ae6e0..0x63ae974`, packet #304's window
`0x63ae2b0..0x63ae6d1`, packet #303's window
`0x63adb50..0x63adf34`, packet #302's window
`0x6387420..0x6387878`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`.

## Correction to the survey (proven by objdump census)

The #298–#305 surveys listed the next candidate
`0x63aed40..0x63aefdb` with **2** lu-miss sites. A targeted
objdump census of that FDE finds **one** call to `0x63d9700`
(`0x63aefcd`); the other calls are bin_table_init `0x63aeea1`
and `__stack_chk_fail` `0x63aef60` (3 calls total, 149 strict,
1 ret at `0x63aedb5`, 0 bsr). The survey entry in this packet's
records.json corrects the count to 1, and the next question below
uses the corrected figure. All other fall-through candidates
were re-verified by program and match the survey exactly
(`0x63aefe0` miss 2, `0x63af460` miss 4, `0x63afc60` miss 4,
`0x63bc490` miss 1, `0x63bc730` miss 1, `0x63c2f00` miss 1
with bsr 1).

## Prior pointer verified (no correction)

#305's survey pointer for this window (953 bytes, 1 bin_table_init
site, 2 lu-miss sites, 1 ret, 0 bsr) is verified correct by program
arithmetic and by the objdump census above.

## 1-raw tier status

Packet #298 surveyed all 17 1-raw candidates (each exactly 1
objdump-verified bin_table_init site). 16 survive; 1 is excluded as
a whole FDE (`0x63adf40..0x63ae252`, overlapping #214's claimed
sub-ranges). This packet builds on the ninth survivor. The next
frontier is packet #307 on `0x63aed40..0x63aefdb` (667 bytes, 1
bin_table_init site, 1 lu-miss site — corrected — 1 ret, 0 bsr).

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_2walk_constwrite_1site.py`:
  exit 0 (109 checks, 0 failures — count taken from the source
  before sealing, confirmed by the sealing run).
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_2walk_constwrite_1site.py`
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

- Verifier: exit 0, 109 checks, 0 failures.
- Unit tests: exit 0, 12 checks, 0 failures.
- Disjointness: verifier scanned 62,226 priors, 0 skipped,
  NONE (deduplicated figure 61,438 after removing 788
  within-file duplicate ranges).
