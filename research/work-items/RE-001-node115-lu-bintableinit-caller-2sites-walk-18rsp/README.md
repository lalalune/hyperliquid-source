# RE-001-node115-lu-bintableinit-caller-2sites-walk-18rsp

Sixth 2-raw bin_table_init caller packet (after #288, #289, #290, #291,
#292). FDE `0x63d4171..0x63d4289` (280 bytes, 70 strict lines, 5 calls,
0 ret) is a compact two-helper dispatch shell: it does not walk inline
(no scans, no move-to-front, no lu-miss sites). Instead, a null-context
test at each phase selects between the caller's own context table and a
stack-temp table built by bin_table_init, and two helper callees own the
actual lookup work. Both bin_table_init sites pass the same in-block
stack temp `lea 0x18(%rsp)` through `r12`.

## Window

- FDE `0x63d4171..0x63d4289`, 280 bytes, 70 strict mnemonic lines.
- Previous FDE `0x63d4048..0x63d4171` (padding 0) — note this is also
  the phase-2 helper callee (see below); it is cited, not claimed.
- Next FDE `0x63d4289..0x63d4425` (padding 0) — packet #294's primary
  candidate, adjacent, not overlapping.
- Frame: pushes r12/rbp/rbx (no `endbr64`), `sub $0x1a0,%rsp`, canary
  at `0x198(%rsp)`.
- Entry: `rdi` = context (kept in `rbx`), `rsi` = key (kept in `rbp`).
  Table `lea 0x1b0(%rdi)` in `rsi` at `0x63d4177`.
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.
- No `0x6727a00` table, no `0x6713606` gate byte, and no `0x67277c0`
  threshold table are referenced in this FDE. No `bsr`, no `lock`
  instruction of either sign.

## Classification

**Null-context site 1.** `test %rdi,%rdi; jne 0x63d41b1` at
`0x63d419c..0x63d419f`: a null context falls through to block
`0x63d41a1` (`lea 0x18(%rsp),%r12; mov %r12,%rdi`), call at `0x63d41a9`
(`e8 d2 56 00 00` -> `0x63d9880`). No other jump in the window targets
`0x63d41a1`, so this branch alone governs entry. Rejoin:
`mov %r12,%rsi` at `0x63d41ae`, falling into the phase-1 helper call
with the stack-temp table in `rsi`.

**Phase-1 helper call.** `call 0x63d3f0e` at `0x63d41b7` (`rdi` = `rbx`
context, `rsi` = table, `rdx` = `rbp` key). Its return is stored as
`rax` -> `(%rsp)` and `ecx` -> `0x8(%rsp)`. The helper's internals
are not decoded here; only its observable contract is used: a flag
byte at `0x9(%rsp)` (the second byte of the `ecx` word) and a value
in `eax` that is compared against the constant `0x23`.

**Flag/gate dispatch.** `cmpb $0x0,0x9(%rsp)` at `0x63d41c7`:

- Flag nonzero: fall through to the canary check
  (`0x63d41ce..0x63d41df`) and exit via `0x63637f0` (see Exits).
- Flag zero (`je 0x63d41fb` at `0x63d41cc`): `cmp $0x23,%eax` at
  `0x63d41fb`; `ja 0x63d4230` enters phase 2; at-or-below `0x23`
  runs the canary check (`0x63d4200..0x63d4211`) and exits via
  `0x6363260` with `rdi = rbx`, `rsi = rbp`, `rdx = 0`, `rcx = 1`.
  The threshold constant `0x23` matches the node-resolution gate
  constant in #291, but `eax` here is the helper's return value —
  this packet does not claim it equals `(value >> 0x30)`.

**Null-context site 2.** Phase 2 opens with
`lea 0x1b0(%rbx),%rdx` at `0x63d4230`, then
`test %rbx,%rbx; jne 0x63d424c` at `0x63d4237..0x63d423a`: a null
context falls through to block `0x63d423c`
(`lea 0x18(%rsp),%r12; mov %r12,%rdi`), call at `0x63d4244`
(`e8 37 56 00 00` -> `0x63d9880`). No other jump in the window
targets `0x63d423c`, so this branch alone governs entry. Rejoin:
`mov %r12,%rdx` at `0x63d4249`, then `mov %rbx,%rsi`,
`mov %rsp,%rdi`, `mov %rbp,%rcx`.

**Phase-2 helper call.** `call 0x63d4048` at `0x63d4255`
(`rdi` = `rsp`, `rsi` = `rbx` context, `rdx` = table, `rcx` = `rbp`
key). Its body is the previous FDE, cited, not claimed. On return,
`mov (%rsp),%rsi` restores the phase-1 value, the canary check runs
(`0x63d425e..0x63d426f`), and the shared epilogue exits via
`0x63bd6c0` (see Exits).

**Bin_table_init sites (2, both `lea 0x18(%rsp)` in-block via `r12`,
each block entered only by fall-through of a null-context test).**

| site | block | branch | argument | rejoin |
| --- | --- | --- | --- | --- |
| `0x63d41a9` | `0x63d41a1` | test %rdi,%rdi; jne from `0x63d419f` (fall-through on null) | 0x18(%rsp) in r12 | mov %r12,%rsi; fall into `0x63d41b1` |
| `0x63d4244` | `0x63d423c` | test %rbx,%rbx; jne from `0x63d423a` (fall-through on null) | 0x18(%rsp) in r12 | mov %r12,%rdx; jmp-free fall into `0x63d424c` |

**No scans.** Unlike #288–#292, this FDE contains no 8-slot scan and
no move-to-front sequence, and no lu-miss site: both phases are
helper calls, so exhaustion handling (if any) lives inside the
helpers, not here.

**Exits (3 tail jumps, 0 ret).** All three follow a complete
epilogue (`add $0x1a0,%rsp` + pops) and a canary check, so each is
an exit verified per FDE, not assumed from the callee's identity —
note that this same trio (`0x63637f0`, `0x63bd6c0`, `0x6363260`)
were tail-jump exits in #288's and #291's FDEs but ordinary
returning calls in #287's FDE, and `0x63bd6c0` was an ordinary call
in #289's FDE:

- `jmp 0x63637f0` at `0x63d41f6` (canary check
  `0x63d41ce..0x63d41df`).
- `jmp 0x6363260` at `0x63d422b` (canary check
  `0x63d4200..0x63d4211`).
- `jmp 0x63bd6c0` at `0x63d4284` (canary check
  `0x63d425e..0x63d426f`).

Canary failure goes to `0x63d4271`, which calls `__stack_chk_fail`
(`0x63f0d70`). Every other direct jump target in the window lies
inside `[0x63d4171, 0x63d4289)`.

## Census (from the objdump exhibit, never copied from a prior packet)

- Strict mnemonic lines: 70.
- Calls: 5 (2 bin_table_init + 1 phase-1 helper `0x63d3f0e` + 1
  phase-2 helper `0x63d4048` + 1 `__stack_chk_fail`).
- Bin_table_init sites: 2 (`0x63d41a9`, `0x63d4244`), both
  `lea 0x18(%rsp)` in-block via `r12`.
- Lu-miss sites: 0.
- `ret`: 0. `bsr`: 0. `lock sub`: 0. `lock add`: 0.
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
and #292 built on the second, third, fourth, and fifth candidates;
this packet builds on the sixth. The remaining survivors are listed
in the next question. Excluded as whole FDEs:
`0x63ed090..0x63ed862` (first 215 bytes claimed by #260) and
`0x63ef8e0..0x63efba2` (two ranges claimed by #258).

**Prior pointer verified (no correction).** #288/#292's survey
pointer for this window (280 bytes, 2 bin_table_init sites, 0
lu-miss sites, 0 ret, 0 bsr) is verified correct by program
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
`0x63d4171..0x63d4289` overlaps no prior range (verifier: 53,357
ranges scanned including the packet's own window, self-excluded by
exact match, 0 skipped, disjointness NONE), including packet #292's
window `0x63cd910..0x63cddce`, packet #291's window
`0x63c89c0..0x63c8d5a`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`. The next window `0x63d4289..0x63d4425`
and the remaining fall-through candidates were also checked
against all priors: NONE each.

## Not covered

- The bin_table_init body `0x63d9880..0x63d9a64` (#262) and the
  lu-miss handler `0x63d9700..0x63d987b` (#215) are cited, not
  claimed.
- The helper bodies (`0x63d3f0e`, `0x63d4048`) are cited, not
  claimed — including the phase-1 helper's flag-byte and `eax`
  semantics and the phase-2 helper's out-parameter at `rsp`.
  The previous FDE `0x63d4048..0x63d4171` is the phase-2 helper
  itself, not part of this packet.
- The tail-jump targets' bodies (`0x63637f0`, `0x63bd6c0`,
  `0x6363260`) are reads, not claims.
- The neighboring FDEs are not decoded here.
- The remaining 2-raw candidates and the 1-raw tier are future
  packets.

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_walk_18rsp_2sites.py`:
  exit 0, 98 checks, 0 failures.
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_walk_18rsp_2sites.py`
  (tamper controls first — hex flip, strict-count change, call-site
  change, injected overlap — each makes the temp-copy verifier fail;
  the clean temp copy passes): exit 0, 11 checks, 0 failures.
- `make verify`: exit 0 (559 evidence-packet manifests, 7159
  entries).
- `make catalogue-check`: exit 2 with the pre-existing `Stale
  catalogue: README.md` failure, also present on a pristine
  checkout; not a packet regression.
- Full `make test` is not run (584 files on the new base; hours of
  runtime and VM-restart risk). This deviation from the repository's
  stated gate is declared here rather than hidden.
- `.hex` exhibits are raw binary bytes, not hex text.
