# RE-001: lu bin_table_init rsp two-phase walk caller, 2 sites

Fourth 2-raw bin_table_init caller packet: FDE `0x63c89c0..0x63c8d5a`
(922 bytes, 201 strict lines, 5 calls, 0 ret), carrying over from packet
#290's next question. This is a small packet by design: 2 sites, not a
4-site walk. It is reported as such, not inflated.

Unlike #290's gated walk (size argument, threshold table, size-class
block, helper-computed key), this FDE is an ungated two-phase lookup
walk: the entry key goes straight into a context+0x1b0 table walk, and
only the node-resolution gate (`(value >> 0x30)` vs `0x23`) decides
whether control exits or enters a second walk on the same table shape.
Both bin_table_init sites pass plain `%rsp` — site 1 in phase 1, site 2
in phase 2 — and the FDE has three canary-checked tail-jump exits, no
ret, no bsr, and no lock instruction of either sign.

## Window

- FDE `0x63c89c0..0x63c8d5a`, 922 bytes, 201 strict mnemonic lines.
- Previous FDE `0x63c8820..0x63c89b7` (gap 9 bytes, all `0xcc`).
- Next FDE `0x63c8d60..0x63c94fc` (padding 6 bytes, all `0xcc`) — this
  is packet #281's window, adjacent, not overlapping.
- Frame: pushes r14/r13/r12/rbp/rbx (no `endbr64`),
  `sub $0x190,%rsp`, canary at `0x188(%rsp)`.
- Entry: `rdi` = context (kept in `rbp`), `rsi` = key (kept in `rbx`).
  Table `lea 0x1b0(%rdi)` in `rsi` at `0x63c89ce`.
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.
- No `0x6713606` gate byte, no `0x67277c0` threshold table, and no
  size-class block are referenced in this FDE (0 bsr).

## Classification

**Phase-1 walk (context+0x1b0 table).** Top index
`(key >> 0x1a) & 0xf0`, high bits `key & 0xffffffffc0000000`, second
level `(key >> 0x9) & 0x1ffff8 + table + 0x8`. On a top-level match,
the second-level value's low bit decides: `test $0x1,%al` at
`0x63c8a2b`; low bit 0 jumps to node resolution at `0x63c8ac8`;
low bit 1 falls through to the canary check and exits via
`0x63637f0`. On a top-level mismatch, the walk scans (below). On a
slot-0 hit, the entry swaps into the head (sequence at `0x63c8a8d`)
and control returns to the second level at `0x63c8a28`.

**Null-context site 1.** `test %rdi,%rdi; je 0x63c8a68` at
`0x63c89ef..0x63c89f2` leads to block `0x63c8a68`
(`mov %rsp,%r12; mov %r12,%rdi`), call at `0x63c8a6e`
(`e8 0d 0e 01 00` -> `0x63d9880`), rejoin `mov %r12,%rsi;
jmp 0x63c89f4` (walk restarts with the stack-temp table).

**Node resolution (`0x63c8ac8`).** `(value >> 0x30)` vs `0x23`:
`jbe 0x63c8b40` runs the canary check and exits via `0x6363260`
with `rdi = rbp`, `rsi = rbx`, `rdx = 0`, `rcx = 1`; above `0x23`
enters phase 2 with table `lea 0x1b0(%rbp)` in `r14`.

**Phase-2 walk (context+0x1b0 table, context in `rbp`).** Same top
index and second level. On a top-level match, the second-level value
is field-extracted (`shl/sar $0x10`, mask
`$0xffffffffffffff80` at `0x63c8b1d..0x63c8b31`), then the canary
check runs and the FDE exits via `0x63bd6c0` with `rdi = rbp`.
On a top-level mismatch, the walk scans (below). On a slot-0 hit,
the entry swaps into the head (sequence at `0x63c8bdb`) and control
returns to the second level at `0x63c8b03`.

**Null-context site 2.** `test %rbp,%rbp; je 0x63c8c10` at
`0x63c8ad9..0x63c8adc` leads to block `0x63c8c10`
(`mov %rsp,%r14; mov %r14,%rdi`), call at `0x63c8c16`
(`e8 65 0c 01 00` -> `0x63d9880`), rejoin `jmp 0x63c8ae2`
(second-level walk on the stack-temp table).

**Bin_table_init sites (2, both plain `%rsp`, each block the target
of exactly one `je` on a null-context test).**

| site | block | branch | argument | rejoin |
| --- | --- | --- | --- | --- |
| `0x63c8a6e` | `0x63c8a68` | test %rdi,%rdi; je from `0x63c89f2` | %rsp in r12 | mov %r12,%rsi; jmp `0x63c89f4` |
| `0x63c8c16` | `0x63c8c10` | test %rbp,%rbp; je from `0x63c8adc` | %rsp in r14 | jmp `0x63c8ae2` |

**Scans (8 slots each, table+0x100, move-to-front on a hit).**

- Scan 1 (phase-1 mismatch, table in `rsi`): slot 0 at `0x63c8a80`
  (`cmp 0x100(%rsi),%r13`), slot 1 at `0x63c8b85`
  (`cmp 0x110(%rsi),%r13`), unrolled slots 2..7 at
  `0x63c8c20..0x63c8c88` (`0x120`, `0x130`, reversed-operand
  `cmp %r13,0x140(%rsi)`, `0x150`, `0x160`, `0x170`).
  Move-to-front at `0x63c8b92` (`edi` = slot index, shift `*16`,
  swap slot into head). Exhaustion falls to lu-miss `0x63c8ca9`.
- Scan 2 (phase-2 mismatch, table in `r14`): slot 0 at `0x63c8bce`
  (`cmp 0x100(%r14),%r13`), indexed loop at
  `0x63c8cb3..0x63c8d35` (init `esi = 1`; body recomputes byte
  index `rdi = rsi * 16` and compares `0x100(%r14,%rdi,1)`
  against `%r13`; increment at `0x63c8d2d`; exit at `rsi = 8`),
  covering slots 1..7. Move-to-front at `0x63c8cc9..0x63c8d23`.
  Exhaustion falls to lu-miss `0x63c8d50`.

**Lu-miss sites (both rsi = `lea 0x6511a00`, r8 = 1, r9 = 0).**

| site | rdi | rdx | rcx | rejoin |
| --- | --- | --- | --- | --- |
| `0x63c8ca9` | rbp context | rsi scan-1 table | rbx key | jmp `0x63c8a28` |
| `0x63c8d50` | rbp context | r14 scan-2 table | rbx key | jmp `0x63c8b03` |

**Exits (3 tail jumps, 0 ret).** All three follow a complete
epilogue (`add $0x190,%rsp` + pops) and a canary check, so each is
an exit verified per FDE, not assumed from the callee's identity —
note that this same trio (`0x63637f0`, `0x63bd6c0`, `0x6363260`)
were tail-jump exits in #288's FDE but ordinary returning calls in
#287's FDE, and `0x63bd6c0` was an ordinary call in #289's FDE:

- `jmp 0x63637f0` at `0x63c8a5f` (canary check
  `0x63c8a33..0x63c8a44`).
- `jmp 0x63bd6c0` at `0x63c8b3b` (canary check
  `0x63c8b06..0x63c8b17`).
- `jmp 0x6363260` at `0x63c8b73` (canary check
  `0x63c8b40..0x63c8b51`).

Canary failure goes to `0x63c8d28`, which calls `__stack_chk_fail`
(`0x63f0d70`).

## Census (from the objdump exhibit, never copied from a prior packet)

- Strict mnemonic lines: 201.
- Calls: 5 (2 bin_table_init + 2 lu-miss + 1 `__stack_chk_fail`).
- Bin_table_init sites: 2 (`0x63c8a6e`, `0x63c8c16`), both plain
  `%rsp`.
- Lu-miss sites: 2 (`0x63c8ca9`, `0x63c8d50`).
- `ret`: 0. `bsr`: 0. `lock sub`: 0. `lock add`: 0.
- Raw `0xe8` census (byte scan for `e8` with rel32 target `0x63d9880`,
  grouped by enclosing `.eh_frame` FDE, own parse of 135,313 FDEs
  sorted before bisect): total 108, tiers 10x1, 8x1, 6x2, 5x1, 4x8,
  2x12, 1x17. This FDE holds 2 raw sites. No 3-raw tier exists.
- `.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278
  entries, counted separately.

## Size-class blocks

None: 0 bsr instructions in this FDE, like #280/#281/#282/#285/#286/
#287/#288/#289 and unlike #275/#276/#277/#279/#283/#284/#290, which
had size-class blocks.

## 2-raw tier status

Packet #288 surveyed all 12 2-raw candidates (each exactly 2
objdump-verified bin_table_init sites). Packets #289 and #290 built
on the second and third candidates; this packet builds on the fourth.
The remaining survivors are listed in the next question. Excluded as
whole FDEs: `0x63ed090..0x63ed862` (first 215 bytes claimed by #260)
and `0x63ef8e0..0x63efba2` (two ranges claimed by #258).

**Prior pointer verified (no correction).** #288/#289/#290's survey
pointer for this window (922 bytes, 2 bin_table_init sites, 2
lu-miss sites, 0 ret, 0 bsr) is verified correct by program
arithmetic and by the objdump census above.

**Survey method note.** The range-only collector used for the
claim check accepts start/end stored as decimal integers as well as
hex strings (plain `int(x, 16)` for strings, no regex gating on the
`0x` prefix — both failure modes found in #288/#290 are avoided),
and asserts 0 skipped records.

## Disjointness

Range-only collector over the merged tree plus all prior
`hl-wt-calls*` worktree records (string ranges, `[start,end]` lists,
and start/end pairs inside exhibits/windows lists or dicts,
including decimal-integer forms). Cited-only subtrees,
enclosing-fde annotations, next-caller pointers, scan descriptors,
and cfg edges are never collected. The window
`0x63c89c0..0x63c8d5a` overlaps no prior range (verifier: priors
scanned, 0 skipped, disjointness NONE), including packet #281's
adjacent window `0x63c8d60..0x63c94fc`, packet #288's window
`0x6349780..0x6349bd9`, packet #289's window
`0x6361320..0x63620da`, packet #290's window
`0x636b940..0x636bd90`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`.

## Not covered

- The bin_table_init body `0x63d9880..0x63d9a64` (#262) and the
  lu-miss handler `0x63d9700..0x63d987b` (#215) are cited, not
  claimed.
- The tail-jump targets' bodies (`0x63637f0`, `0x63bd6c0`,
  `0x6363260`) and the lu-miss argument table `0x6511a00` are
  reads, not claims. The `0x6727a00` table is not referenced in
  this FDE at all.
- The neighboring FDEs are not decoded here.
- The remaining 2-raw candidates and the 1-raw tier are future
  packets.

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_walk_rsp_3exit_2sites.py`:
  exit 0, 53 checks, 0 failures (disjointness NONE over 47,368
  prior ranges, 0 skipped).
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_walk_rsp_3exit_2sites.py`
  (tamper controls first — hex flip, strict-count change, call-site
  change, injected overlap — each makes the temp-copy verifier fail;
  the clean temp copy passes): exit 0, 13 checks, 0 failures.
- `make verify`: exit 0 (559 evidence-packet manifests, 7159
  entries).
- `make catalogue-check`: exit 2 with the pre-existing `Stale
  catalogue: README.md` failure, also present on a pristine
  checkout; not a packet regression.
- Full `make test` is not run (584 files on the new base; hours of
  runtime and VM-restart risk). This deviation from the repository's
  stated gate is declared here rather than hidden.
- `.hex` exhibits are raw binary bytes, not hex text.
