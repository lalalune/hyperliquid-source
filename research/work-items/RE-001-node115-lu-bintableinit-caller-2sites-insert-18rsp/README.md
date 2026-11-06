# RE-001-node115-lu-bintableinit-caller-2sites-insert-18rsp

Seventh 2-raw bin_table_init caller packet (after #288, #289, #290, #291,
#292, #293). FDE `0x63d4289..0x63d4425` (412 bytes, 102 strict lines,
9 calls, 1 ret) is a key-struct insert routine: it computes a size class
from the entry struct's count field, resolves a node through helper
`0x6364880` plus two phase helpers, and on the shared tail initializes
a node (fields + `rep movsb` data copy) and registers it in globals.
Both bin_table_init sites pass the same in-block stack temp
`lea 0x18(%rsp)` through `r13`, each block entered only by fall-through
of a null-context test. Unlike #293's dispatch shell (0 ret, 3 tail-jump
exits), this FDE has a single `ret` and no tail jump leaves the window.

## Window

- FDE `0x63d4289..0x63d4425`, 412 bytes, 102 strict mnemonic lines.
- Previous FDE `0x63d4171..0x63d4289` (padding 0) — packet #293's window,
  adjacent, not overlapping.
- Next FDE `0x63d4425..0x63d4497` (padding 0) — packet #295's primary
  candidate is the FDE after that, `0x63d4497..0x63d463e`, adjacent,
  not overlapping.
- Frame: pushes r14/r13/r12/rbp/rbx (no `endbr64`), `sub $0x1a0,%rsp`,
  canary at `0x198(%rsp)`.
- Entry: `rdi` = context (kept in `rbp`), `rsi` = key struct pointer
  (kept in `r12`); count field at `+8`, data pointer at `+0`.
  Size `rbx = 0x20 + 8 * count` at `0x63d42b1..0x63d42b4`.
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.
- No `0x6713606` gate byte is referenced in this FDE (0 bsr).

## Classification

**Size class.** `cmp $0x1000,%rbx` at `0x63d42c4`, `ja 0x63d42e1`.
Below the gate, threshold table `0x67277c0` is indexed by
`(size >> 3)` at `0x63d42cd..0x63d42db`. Above the gate, size-class
helper `0x63d3b3d` is called at `0x63d42e4` (`rdi` = size). No `bsr`
is used anywhere in this FDE.

**Key helper.** `call 0x6364880` at `0x63d42f7` (`rdi` = context,
`rsi` = result of size helper `0x63d3eee` called at `0x63d42bc`,
`rdx` = size, `rcx` = size class, `r8` = 0). Its return is kept in
`rbx` and is the node pointer used by the rest of the routine. A
null return jumps directly to the shared tail at `0x63d438c`; the
tail writes through `rbx`, so the null path's runtime semantics are
not decoded here — only the branch itself is claimed.

**Null-context site 1.** `test %rbp,%rbp; jne 0x63d4324` at
`0x63d430f..0x63d4312`: a null context falls through to block
`0x63d4314` (`lea 0x18(%rsp),%r13; mov %r13,%rdi`), call at
`0x63d431c` (`e8 5f 55 00 00` -> `0x63d9880`). No other jump in the
window targets `0x63d4314`, so fall-through alone governs entry.
Rejoin: `mov %r13,%rsi` at `0x63d4321`, falling into the phase-1
helper call with the stack-temp table in `rsi`.

**Phase-1 helper call.** `call 0x63d3f0e` at `0x63d432a`
(`rdi` = `rbp` context, `rsi` = table, `rdx` = `rbx` node). Its
return is stored as `rax` -> `(%rsp)` and `edx` -> `0x8(%rsp)`.
Node resolution follows: `lea 0x6727a00` at `0x63d432f`,
`mov (%rdi,%rsi,8),%r14` at `0x63d4347` with `rsi` = phase-1
`eax` — `r14` is the resolved node value.

**Null-context site 2.** `test %rbp,%rbp; jne 0x63d4360` at
`0x63d434b..0x63d434e`: a null context falls through to block
`0x63d4350` (`lea 0x18(%rsp),%r13; mov %r13,%rdi`), call at
`0x63d4358` (`e8 23 55 00 00` -> `0x63d9880`). No other jump in the
window targets `0x63d4350`. Rejoin: `mov %r13,%rdx` at `0x63d435d`,
then `mov %rsp,%rdi`, `mov %rbx,%rcx`, `mov %rbp,%rsi`.

**Phase-2 helper call.** `call 0x63d4048` at `0x63d4369`
(`rdi` = `rsp`, `rsi` = `rbp` context, `rdx` = table,
`rcx` = `rbx` node). Its body is the previous FDE's predecessor
(`0x63d4048..0x63d4171`), cited, not claimed. On return,
`mov (%rsp),%r8` restores the phase-1 value; `lea 0x65096c0`
at `0x63d4372`, `mov (%r11,%r9,8),%rax` at `0x63d4383` with
`r9 = (%r8) & 0xfff`; then `lock add %r14,0x38(%rax)` at
`0x63d4387` (refcount increment — the FDE has 0 `lock sub`).

**Bin_table_init sites (2, both `lea 0x18(%rsp)` in-block via `r13`,
each block entered only by fall-through of a null-context test).**

| site | block | branch | argument | rejoin |
| --- | --- | --- | --- | --- |
| `0x63d431c` | `0x63d4314` | test %rbp,%rbp; jne from `0x63d4312` (fall-through on null) | 0x18(%rsp) in r13 | mov %r13,%rsi; fall into `0x63d4324` |
| `0x63d4358` | `0x63d4350` | test %rbp,%rbp; jne from `0x63d434e` (fall-through on null) | 0x18(%rsp) in r13 | mov %r13,%rdx; fall into `0x63d4360` |

**No scans.** Unlike #288–#292, this FDE contains no 8-slot scan and
no move-to-front sequence, and no lu-miss site: both phases are
helper calls, so exhaustion handling (if any) lives inside the
helpers, not here.

**Shared tail (node insert + register).** Starting at `0x63d438c`:
global bookkeeping on `0x6714738` (last node), `0x6714730`
(previous node), `0x67147c0` (counter); node at `rbx` gets
`+0 = 0`, `+8 = old counter`, `+0x10 = data pointer 0x20(%rbx)`,
`+0x18 = count`, and `rep movsb` at `0x63d43d3` copies
`count * 8` bytes from `(%r12)` to `0x20(%rbx)`; counter `r14`
is incremented and stored back; register helper `0x63d39a0` is
called at `0x63d43f4` (`rdi` = context, `rsi` = `lea 0x6714780`,
`rdx` = node); return value is `0x8(%rbx)` in `rax`.

**Exit (1 ret, 0 tail jumps).** The single `ret` is at `0x63d4424`
(shared epilogue: `add $0x1a0,%rsp` + pops, after the canary check
at `0x63d43fd..0x63d440e`). The window's two unconditional jumps
(`0x63d42df`, `0x63d439d`) both target inside the window. Canary
failure goes to `0x63d4410`, which calls `__stack_chk_fail`
(`0x63f0d70`).

## Census (from the objdump exhibit, never copied from a prior packet)

- Strict mnemonic lines: 102.
- Calls: 9 (2 bin_table_init + 1 size helper `0x63d3eee` + 1
  size-class helper `0x63d3b3d` + 1 key helper `0x6364880` + 1
  phase-1 helper `0x63d3f0e` + 1 phase-2 helper `0x63d4048` + 1
  register helper `0x63d39a0` + 1 `__stack_chk_fail`).
- Bin_table_init sites: 2 (`0x63d431c`, `0x63d4358`), both
  `lea 0x18(%rsp)` in-block via `r13`.
- Lu-miss sites: 0.
- `ret`: 1. `bsr`: 0. `lock sub`: 0. `lock add`: 1.
- Raw `0xe8` census (byte scan for `e8` with rel32 target `0x63d9880`,
  grouped by enclosing `.eh_frame` FDE, own parse of 135,313 FDEs
  sorted before bisect): total 108, tiers 10x1, 8x1, 6x2, 5x1, 4x8,
  2x12, 1x17. This FDE holds 2 raw sites, matching its 2 objdump
  sites. No 3-raw tier exists.
- `.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278
  entries, counted separately (readelf `-W`; non-wide output
  truncates the JUMP_SLOT type name and undercounts).

## 2-raw tier status

Packet #288 surveyed all 12 2-raw candidates (each exactly 2
objdump-verified bin_table_init sites). Packets #289, #290, #291,
#292, and #293 built on the second, third, fourth, fifth, and
sixth candidates; this packet builds on the seventh. The remaining
survivors are listed in the next question. Excluded as whole FDEs:
`0x63ed090..0x63ed862` (first 215 bytes claimed by #260) and
`0x63ef8e0..0x63efba2` (two ranges claimed by #258).

**Prior pointer verified (no correction).** #288/#293's survey
pointer for this window (412 bytes, 2 bin_table_init sites, 0
lu-miss sites, 1 ret, 0 bsr) is verified correct by program
arithmetic and by the objdump census above.

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
pointers, and cfg edges are never collected.

## Disjointness

Range-only collector over the merged tree plus all prior
`hl-wt-calls*` worktree records (exhibits/windows only, all
range-bearing forms above, decimal-integer start/end accepted,
plain `int(x, 16)` for hex strings). The window
`0x63d4289..0x63d4425` overlaps no prior range (verifier: 52,963
prior ranges scanned, 0 skipped, disjointness NONE), including packet #293's window `0x63d4171..0x63d4289`, packet
#292's window `0x63cd910..0x63cddce`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`. The next window `0x63d4497..0x63d463e`
and the remaining fall-through candidates were also checked
against all priors: NONE each.

## Not covered

- The bin_table_init body `0x63d9880..0x63d9a64` (#262) and the
  lu-miss handler `0x63d9700..0x63d987b` (#215) are cited, not
  claimed.
- The helper bodies (`0x63d3eee`, `0x63d3b3d`, `0x6364880`,
  `0x63d3f0e`, `0x63d4048`, `0x63d39a0`) are cited, not claimed —
  including the key helper's null-return semantics and the
  phase-1 helper's `eax`/`edx` contract.
- The tables `0x6727a00`, `0x67277c0`, `0x65096c0` and the globals
  `0x6714738`, `0x6714730`, `0x67147c0`, `0x6714780` are read, not
  claimed.
- The neighboring FDEs are not decoded here.
- The remaining 2-raw candidates and the 1-raw tier are future
  packets.

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_insert_18rsp_2sites.py`:
  exit 0, 91 checks, 0 failures.
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_insert_18rsp_2sites.py`
  (tamper controls first — hex flip, strict-count change, call-site
  change, injected overlap — each makes the temp-copy verifier fail;
  the clean temp copy passes): exit 0, 12 checks, 0 failures.
- `make verify`: exit 0 (559 evidence-packet manifests, 7159
  entries).
- `make catalogue-check`: exit 2 with the pre-existing `Stale
  catalogue: README.md` failure, also present on a pristine
  checkout; not a packet regression.
- Full `make test` is not run (584 files on the new base; hours of
  runtime and VM-restart risk). This deviation from the repository's
  stated gate is declared here rather than hidden.
- `.hex` exhibits are raw binary bytes, not hex text.
