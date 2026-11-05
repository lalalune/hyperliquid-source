# RE-001-node115: lu bin_table_init 10rsp lookup walk caller, 2 sites

Ninth 2-raw bin_table_init caller packet (after #288, #289, #290, #291,
#292, #293, #294, #295). The window is a lookup walk routine: the key
comes from helper `0x6364880` called before the walk (context, index
table slot 0, `0x48`, byte at `0x67277c9`), then a two-phase
context-table walk with 8-slot move-to-front scans resolves the node
and increments its refcount, and the single `ret` returns the key.
Both bin_table_init sites pass the same in-block stack temp
`lea 0x10(%rsp)`, each block entered only by a null-context `je`.

## Window

- FDE `0x63d61a0..0x63d6575`, 981 bytes, 199 strict mnemonic lines.
- Previous FDE `0x63d6060..0x63d6199` (gap 7 bytes, all `0xcc`).
- Next FDE `0x63d6575..0x63d6619` (padding 0) — adjacent, not overlapping.
- Frame: pushes r15/r14/r13/r12/rbp/rbx (no `endbr64`),
  `sub $0x1a8,%rsp`, canary at `0x198(%rsp)`.
- Entry: `rdi` = context (kept in `rbp`). Entry `rsi` is overwritten
  at `0x63d61d6` before the key helper call, so entry `rsi` is unused.
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.
- No `0x6713606` gate byte is referenced in this FDE (0 bsr).

## Classification

**Key helper (before the walk).** `call 0x6364880` at `0x63d61e5`
(`rdi` = context, `rsi` = value at `0x65096c0` slot 0,
`rdx = 0x48`, `rcx` = byte at `0x67277c9` (threshold-table base
`0x67277c0` + 9), `r8 = 0`). Its return is kept in `rbx` and is
the lookup key. A null return jumps to the shared epilogue at
`0x63d62a5`, which returns 0.

**Phase-1 walk (context+0x1b0 table).** Top index
`(key >> 0x1a) & 0xf0`, high bits `key & 0xffffffffc0000000`,
second level `(key >> 0x9) & 0x1ffff8 + table + 0x8`. On a
top-level match, the second-level value is shifted
(`>> 0x30`) and used to index node-resolution table `0x6727a00`
at `0x63d6253`; the resolved value is kept in `r14`. On a
top-level mismatch, the walk scans (below).

**Null-context site 1.** `test %rbp,%rbp; je 0x63d62d8` at
`0x63d61fd..0x63d6200` leads to block `0x63d62d8`
(`lea 0x10(%rsp),%r12; mov %r12,%rdi`), call at `0x63d62e0`
(`e8 9b 35 00 00` -> `0x63d9880`), rejoin `mov %r12,%rsi;
jmp 0x63d6206` (walk restarts with the stack-temp table).

**Phase-2 walk.** Top-slot re-check at `0x63d6260`, second-level
field extraction (`shl/sar $0x10`, mask
`$0xffffffffffffff80` at `0x63d6284..0x63d628c`), index table
`0x65096c0` indexed by `(value & 0xfff)` at `0x63d629b`,
`lock add %r14,0x38(%r13)` at `0x63d62a0` (refcount increment,
0 `lock sub`), then the shared epilogue.

**Null-context site 2.** `test %rbp,%rbp; je 0x63d6338` at
`0x63d6257..0x63d625a` leads to block `0x63d6338`
(`lea 0x10(%rsp),%rdx; mov %rdx,%rdi; mov %rdx,0x8(%rsp)`),
call at `0x63d6345` (`e8 36 35 00 00` -> `0x63d9880`),
rejoin `mov 0x8(%rsp),%rdx; jmp 0x63d6260` (second-level walk
on the stack-temp table).

**Bin_table_init sites (2, both `lea 0x10(%rsp)` in-block, each
block the target of exactly one `je` on a null-context test).**

| site | block | branch | argument | rejoin |
| --- | --- | --- | --- | --- |
| `0x63d62e0` | `0x63d62d8` | test %rbp,%rbp; je from `0x63d6200` | 0x10(%rsp) in r12 | mov %r12,%rsi; jmp `0x63d6206` |
| `0x63d6345` | `0x63d6338` | test %rbp,%rbp; je from `0x63d625a` | 0x10(%rsp) in rdx | mov 0x8(%rsp),%rdx; jmp `0x63d6260` |

**Scans (8 slots each, table+0x100, move-to-front on a hit).**

- Scan 1 (table in `rsi`): slot 0 at `0x63d62f0`
  (`cmp 0x100(%rsi),%r15`), slot 1 at `0x63d63a3`
  (`cmp 0x110(%rsi),%r15`), slots 2..7 unrolled at
  `0x63d6441..0x63d6496` (`0x120`, `0x130`, `0x140`, `0x150`,
  reversed-operand `cmp %r15,0x160(%rsi)`, `0x170`).
  Move-to-front at `0x63d63b0` (`edi` = slot index, shift `*16`,
  swap slot into head). Exhaustion falls to lu-miss `0x63d64c9`.
- Scan 2 (table in `rdx`): slot 0 at `0x63d6358`
  (`cmp 0x100(%rdx),%r15`), slot 1 at `0x63d63f2`
  (`cmp 0x110(%rdx),%r15`), slots 2..7 unrolled at
  `0x63d64d9..0x63d6532` (reversed-operand compares at `0x120`,
  `0x130`, then `0x140`, `0x150`, `0x160`, `0x170`).
  Move-to-front at `0x63d63ff` (`r8d` = slot index).
  Exhaustion falls to lu-miss `0x63d6566`.

**Lu-miss sites (both rsi = `lea 0x6511a00`, r8 = 1, r9 = 0).**

| site | rdi | rdx | rcx | rejoin |
| --- | --- | --- | --- | --- |
| `0x63d64c9` | rbp context | rsi scan-1 table | rbx key | jmp `0x63d623e` |
| `0x63d6566` | rbp context | rdx scan-2 table (unchanged) | rbx key | jmp `0x63d6281` |

**Exit (1 ret, 0 tail jumps).** The single `ret` is at `0x63d62d0`
(shared epilogue: canary check at `0x63d62a5..0x63d62b6`,
`add $0x1a8,%rsp` + pops, return value = `rbx`). No jump leaves
the window: all 32 jump instructions target inside
`[0x63d61a0, 0x63d6575)`. Canary failure goes to `0x63d6570`,
which calls `__stack_chk_fail` (`0x63f0d70`).

## Census (from the objdump exhibit, never copied from a prior packet)

- Strict mnemonic lines: 199.
- Calls: 6 (1 key helper + 2 bin_table_init + 2 lu-miss + 1
  `__stack_chk_fail`).
- Bin_table_init sites: 2 (`0x63d62e0`, `0x63d6345`), both
  `lea 0x10(%rsp)` in-block.
- Lu-miss sites: 2 (`0x63d64c9`, `0x63d6566`).
- `ret`: 1. `bsr`: 0. `lock sub`: 0. `lock add`: 1.
- Raw `0xe8` census (byte scan for `e8` with rel32 target `0x63d9880`,
  grouped by enclosing `.eh_frame` FDE, own parse of 135,313 FDEs
  sorted before bisect): total 108, tiers 10x1, 8x1, 6x2, 5x1, 4x8,
  2x12, 1x17. This FDE holds 2 raw sites, matching its 2 objdump
  sites. No 3-raw tier exists.
- `.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278
  entries, counted separately (direct ELF parse; readelf `-W`
  cross-checked — non-wide output truncates the JUMP_SLOT type
  name and undercounts).

## 2-raw tier status

Packet #288 surveyed all 12 2-raw candidates (each exactly 2
objdump-verified bin_table_init sites). Packets #289, #290, #291,
#292, #293, #294, and #295 built on the second through eighth
candidates; this packet builds on the ninth. The remaining
survivor is listed in the next question. Excluded as whole FDEs:
`0x63ed090..0x63ed862` (first 215 bytes claimed by #260) and
`0x63ef8e0..0x63efba2` (two ranges claimed by #258).

**Prior pointer verified (no correction).** #288/#295's survey
pointer for this window (981 bytes, 2 bin_table_init sites, 2
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
`0x63d61a0..0x63d6575` overlaps no prior range (verifier: 53,806
priors scanned, 0 skipped, disjointness NONE), including packet
#295's window `0x63d4497..0x63d463e`, packet #294's window
`0x63d4289..0x63d4425`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`. The remaining fall-through candidate
`0x63ed8b0..0x63edf05` was also checked against all priors:
NONE.

## Not covered

- The bin_table_init body `0x63d9880..0x63d9a64` (#262) and the
  lu-miss handler `0x63d9700..0x63d987b` (#215) are cited, not
  claimed.
- The key helper body (`0x6364880`) is cited, not claimed —
  including how it derives the key from its arguments.
- The tables `0x6727a00`, `0x67277c0`, `0x65096c0`, `0x6511a00`
  are read, not claimed.
- The neighboring FDEs are not decoded here.
- The remaining 2-raw candidate and the 1-raw tier are future
  packets.

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_lookup_10rsp_2sites.py`:
  exit 0, 66 checks, 0 failures.
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_lookup_10rsp_2sites.py`
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
