# RE-001: lu bin_table_init rsp walk caller, 2 sites

## Question

Packet #287 exhausted the 4-raw bin_table_init caller tier (13 caller packets
#275-#287) and found no 3-raw tier. This packet surveys the 2-raw tier (12
FDEs) and builds on its first candidate that is genuinely unclaimed with
objdump-verified bin_table_init sites: FDE `0x6349780..0x6349bd9`.

## Answer

A two-site caller. The FDE runs a gated walk in two phases over the same
context table (`context + 0x1b0`, 16-byte entries, 8 slots at `table + 0x100`).
Both bin_table_init sites pass a plain `%rsp` argument, each reached by exactly
one `je` on a zero context, each rejoining its walk with an immediate `jmp`.
There are no `ret` instructions: all three exits are canary-checked tail
jumps. One `bsr` lives in a size-class block on the gate path only; there is
no `lock sub`.

This is a small packet by design: 2 sites, not a 4-site walk. The body says so
plainly.

## Window

- FDE `0x6349780..0x6349bd9`, 1113 bytes, 230 strict mnemonic lines.
- Previous FDE `0x63495b0..0x6349775` (gap 11 bytes, all `0xcc`).
- Next FDE `0x6349be0..0x634eb7c` (padding 7 bytes, all `0xcc`).
- Frame: `sub $0x190,%rsp`, canary at `0x188(%rsp)`.
- Entry: `rdi` = context (kept in `rbp`), `rsi` = key (kept in `rbx`),
  `rdx` = size argument used only on the gate path. Prologue is pushes;
  there is no `endbr64`.

## Classification

### Entry gate

`lea 0x6713606` byte, `cmpb $0x0`, `je 0x6349838`. If the gate byte is
nonzero, control falls into walk phase 1. If it is zero, the gate path runs:

- `cmp $0x1000,%rdx`; if `rdx > 0x1000`, the size-class block at `0x6349980`
  runs (see below) and rejoins the threshold check.
- Else the threshold table at `0x67277c0` is indexed by `(rdx + 7) >> 3`;
  `cmp $0x23` on the loaded byte: `<= 0x23` goes to the canary check at
  `0x6349805` and exits via `0x63637f0`; `> 0x23` enters walk phase 2.

### Size-class block (gate path only, `0x6349980`)

`movabs $0x7000000000000000,%r10; cmp %rdx,%r10; jb 0x634985e`; then
`r8 = 2 * rdx - 1`, `r9 = bsr(r8)` at `0x63499aa` (the FDE's only `bsr`),
`ecx = max(7, r9)`, `rdx -= 1`, `ecx -= 3`, `rsi = -1 << ecx`,
`rdx &= rsi`, `rdx >>= ecx`, `edx &= 3`, `r9 = min(r9, 6)`,
`edx = -0x17 + rdx + 4 * r9`, and `jmp 0x6349859` back into the `0x23`
threshold check.

### Walk phase 1 (context `rdi`)

- Table: `lea 0x1b0(%rdi),%r12`.
- `test %rdi,%rdi; je 0x63498e0` -> bin_table_init site 1:
  block `0x63498e0` (`mov %rsp,%r12; mov %r12,%rdi`),
  call at `0x63498e6` (`e8 95 ff 08 00` -> `0x63d9880`),
  rejoin `jmp 0x63497c2` (next strict line after the call).
- Top index `(key >> 0x1a) & 0xf0` into the table; high bits
  `key & 0xffffffffc0000000` compared against the entry; mismatch goes to
  scan 1.
- Second level `(key >> 0x9) & 0x1ffff8 + table + 0x8`; the loaded value's
  low bit decides: 1 -> canary check at `0x6349805` -> exit `0x63637f0`;
  0 -> node resolution at `0x6349938`.

### Node resolution (`0x6349938`)

`(value >> 0x30)` vs `0x23`: `> 0x23` enters walk phase 2; otherwise the
canary check at `0x6349945` runs and the FDE exits via `0x6363260` with
`rdi = rbp`, `rsi = rbx`, `rdx = 0`, `rcx = 1`.

### Scan 1 (phase 1 mismatch, `0x63498f0`)

Slot 0: `cmp 0x100(%r12),%rcx`; slot 1 at `0x63499d9`:
`cmp 0x110(%r12),%rcx`; unrolled slots 2..7 at `0x6349b07..0x6349b7b`
(`cmp 0x120`, `cmp %rcx,0x130` reversed-operand, `cmp %rcx,0x140`
reversed-operand, `cmp %rcx,0x150` reversed-operand, `cmp 0x160`,
`cmp 0x170`). A hit swaps the slot into the head (slot 0 sequence at
`0x63498fe`; slot >= 1 sequence at `0x63499ed` rejoining the slot-0
sequence at `0x634991a`) and returns to the second level at `0x63497f9`.
Exhaustion falls to lu-miss site 1 at `0x6349b99`, which rejoins the
second level at `0x63497f9`.

### Walk phase 2 (context `rbp`, i.e. the entry `rdi`)

- Table: `lea 0x1b0(%rbp),%r12`.
- `test %rbp,%rbp; je 0x6349a3d` -> bin_table_init site 2:
  block `0x6349a3d` (`mov %rsp,%r12; mov %r12,%rdi`),
  call at `0x6349a43` (`e8 38 fe 08 00` -> `0x63d9880`),
  rejoin `jmp 0x634986e` (next strict line after the call).
- Top index `(key >> 0x1a) & 0xf0` into the table; high bits compared
  against the entry; mismatch goes to scan 2.
- Second level `(key >> 0x9) & 0x1ffff8 + table + 0x8`; the loaded value
  is field-extracted (`shl $0x10`, `sar $0x10`,
  `and $0xffffffffffffff80`), then the canary check at `0x63498a7` runs
  and the FDE exits via `0x63bd6c0` with `rdi = rbp`.

### Scan 2 (phase 2 mismatch, `0x6349a4d`)

Slot 0: `cmp 0x100(%r12),%r10`. Indexed loop at `0x6349a8d..0x6349baa`
(init `r8 = 1`; body recomputes byte index `r9 = r8 * 16` and compares
`0x100(%r12,%r9,1)` against `%r10`; increment at `0x6349ba8`; exit at
`r8 = 8`), covering slots 1..7. A hit swaps into the head (slot 0 sequence
at `0x6349a57`; loop sequence at `0x6349aa8`) and returns to the second
level at `0x63498a4`. Exhaustion falls to lu-miss site 2 at `0x6349bcf`,
which rejoins the second level at `0x63498a4`.

### Lu-miss sites (2)

Both call `0x63d9700` (#215's handler, cited not claimed) with
`rdi = rbp`, `rsi = lea 0x6511a00`, `rdx = r12` (table), `rcx = rbx`
(key), `r8 = 1`, `r9 = 0`: site 1 at `0x6349b99`, site 2 at `0x6349bcf`.

### Exits (3 tail jumps, 0 ret)

All three follow a complete epilogue (`add $0x190,%rsp` + pops) and a
canary check, so each is an exit regardless of the callee's identity:

- `jmp 0x63637f0` at `0x634982d` (canary check `0x6349805`).
- `jmp 0x63bd6c0` at `0x63498d8` (canary check `0x63498a7`).
- `jmp 0x6363260` at `0x6349974` (canary check `0x6349945`).

Canary failure goes to `0x6349ba3`, which calls `__stack_chk_fail`
(`0x63f0d70`).

## Census (from the objdump exhibit, never copied from a prior packet)

- Strict mnemonic lines: 230.
- Calls: 5 (2 bin_table_init + 2 lu-miss + 1 `__stack_chk_fail`).
- Bin_table_init sites: 2 (`0x63498e6`, `0x6349a43`), both plain `%rsp`.
- Lu-miss sites: 2 (`0x6349b99`, `0x6349bcf`).
- `ret`: 0. `bsr`: 1 (`0x63499aa`). `lock sub`: 0.
- Raw `0xe8` census (byte scan for `e8` with rel32 target `0x63d9880`,
  grouped by enclosing `.eh_frame` FDE, own parse of 135,313 FDEs sorted
  before bisect): total 108, tiers 10x1, 8x1, 6x2, 5x1, 4x8, 2x12, 1x17.
  This FDE holds 2 raw sites. No 3-raw tier exists.
- `.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278 entries,
  counted separately.

## 2-raw survey (all 12 candidates, program arithmetic)

| Candidate | Bytes | bti | miss | ret | bsr | Overlaps | Verdict |
|---|---|---|---|---|---|---|---|
| `0x6349780..0x6349bd9` | 1113 | 2 | 2 | 0 | 1 | 0 | BUILD (this packet) |
| `0x6361320..0x63620da` | 3514 | 2 | 4 | 0 | 0 | 0 | survives, next for #289 |
| `0x636b940..0x636bd90` | 1104 | 2 | 2 | 1 | 1 | 0 | survives |
| `0x63c89c0..0x63c8d5a` | 922 | 2 | 2 | 0 | 0 | 0 | survives |
| `0x63cd910..0x63cddce` | 1214 | 2 | 2 | 1 | 1 | 0 | survives |
| `0x63d4171..0x63d4289` | 280 | 2 | 0 | 0 | 0 | 0 | survives |
| `0x63d4289..0x63d4425` | 412 | 2 | 0 | 1 | 0 | 0 | survives |
| `0x63d4497..0x63d463e` | 423 | 2 | 0 | 1 | 0 | 0 | survives |
| `0x63d61a0..0x63d6575` | 981 | 2 | 2 | 1 | 0 | 0 | survives |
| `0x63ed090..0x63ed862` | 2002 | 2 | 2 | 1 | 2 | 1 | EXCLUDED: first 215 bytes `0x63ed090..0x63ed167` claimed by #260 (lu tls-state-continue) |
| `0x63ed8b0..0x63edf05` | 1621 | 2 | 2 | 1 | 2 | 0 | survives |
| `0x63ef8e0..0x63efba2` | 706 | 2 | 0 | 4 | 0 | 2 | EXCLUDED: `0x63ef8e0..0x63ef92e` and `0x63efa50..0x63efa9e` claimed by #258 (lu leaf-write-class) |

Every candidate has exactly 2 objdump-verified bin_table_init sites (raw
count equals true count in all 12 cases here). Prior-pointer check: #287's
survey pointer for this window (1113 bytes, 2 raw) is verified correct;
no correction.

Survey method note: the first collector pass skipped two merged-tree
records files whose `records.json` stores `start`/`end` as decimal
integers (`RE-001-node115-tagged-count`, `RE-001-ingest-behind-check-115`).
The collector was fixed to accept integer start/end alongside hex strings,
and the survey was re-run: 44,192 prior ranges, same verdicts.

## Disjointness

Range-only collector over the merged tree plus all prior `hl-wt-calls*`
worktree records (string ranges, `[start,end]` lists, and start/end pairs
inside exhibits/windows lists or dicts, including decimal-integer forms).
Cited-only subtrees, enclosing-fde annotations, next-caller pointers, scan
descriptors, and cfg edges are never collected. The window
`0x6349780..0x6349bd9` overlaps no prior range. The verifier re-checks
this against the live worktree at run time.

## Not covered

- The bin_table_init body `0x63d9880..0x63d9a64` (#262) and the lu-miss
  handler `0x63d9700..0x63d987b` (#215) are cited, not claimed.
- The tail-jump targets' bodies (`0x63637f0`, `0x63bd6c0`, `0x6363260`),
  the gate byte `0x6713606`, the threshold table `0x67277c0`, and the
  lu-miss argument table `0x6511a00` are reads, not claims.
- The neighboring FDEs are not decoded here.
- The remaining 2-raw candidates and the 1-raw tier are future packets.

## Verification

- Static verifier `tools/node115_lu_bintableinit_caller_walk_rsp_2sites.py`:
  exit 0.
- Own unit tests `tests/test_node115_lu_bintableinit_caller_walk_rsp_2sites.py`
  (tamper controls first, temp-copy verifier): all pass.
- `make verify`: exit 0.
- `make catalogue-check`: reports the pre-existing `Stale catalogue:
  README.md` failure, also present on a pristine checkout; not a packet
  regression.
- Full `make test` is not run (584 files on the new base; hours of runtime
  and VM-restart risk). This deviation from the repository's stated gate is
  declared here rather than hidden.

## Next question

Build packet #289 on the next surviving 2-raw candidate
`0x6361320..0x63620da` (3514 bytes, 2 bin_table_init sites, 4 lu-miss
sites, 0 ret, 0 bsr), after re-verifying its site count and claim status
against prior exhibits. If that candidate fails verification, fall through
the surviving list in the survey table above, in order.
