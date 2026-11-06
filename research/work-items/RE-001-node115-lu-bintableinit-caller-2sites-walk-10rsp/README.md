# RE-001-node115-lu-bintableinit-caller-2sites-walk-10rsp

Third 2-raw bin_table_init caller packet: FDE `0x636b940..0x636bd90`
(1104 bytes, 228 strict lines, 6 calls, 1 ret), carrying over from
packet #289's next question. This is a small packet by design: 2 sites,
not a 4-site walk. It is reported as such, not inflated.

Unlike #289's mutex-guarded three-part routine, this FDE is a pure
lookup walk on a context+0x1b0 table with two null-context
bin_table_init sites, both passing the same stack temp
`lea 0x10(%rsp)` — the same single-temp shape as #287 (which also used
`lea 0x10(%rsp)` at all four sites), but here with only 2 sites, a
single ret exit, a gate-path size-class block (1 bsr), and a `lock add`
refcount increment during node resolution instead of the `lock sub`
decrements seen in #285/#286/#287.

Base: upstream main `05bc2de303c05525b71e7e257426e741bc66a390`
(fetch-confirmed at build time). Target binary
`artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Static analysis only; the target binary is never executed.

## Prior pointer verified (no correction)

Packet #288/#289's survey pointer for this window (1104 bytes, 2
bin_table_init sites, 2 lu-miss sites, 1 ret, 1 bsr) is verified correct
by program arithmetic from the `.eh_frame` bounds (previous FDE ends at
`0x636b937` with a 9-byte `0xcc` gap; next FDE starts exactly at
`0x636bd90`, padding 0 — the next FDE is packet #282's window
`0x636bd90..0x636c49c`, adjacent, not overlapping) and by the objdump
census below. No survey framing is corrected.

## The FDE

- Window: `0x636b940..0x636bd90`, 1104 bytes, 228 strict lines
  (address + bytes field + tab + mnemonic starting with a lowercase
  letter; byte-continuation lines excluded), 6 calls, 1 ret.
- Frame: pushes r15/r14/r13/r12/rbp/rbx (no `endbr64`),
  `sub $0x1a8,%rsp`, canary at `0x198(%rsp)`, one canary check at
  `0x636ba64..0x636ba6d` (`sub %fs:0x28,%rax`, `jne` to the
  `__stack_chk_fail` call at `0x636bd8b`).
- Entry: rdi = context (kept in rbp), rsi = size argument (moved to
  rdx at `0x636b942`). The key is the return value of helper
  `0x6364880` (called at `0x636b99c` with rdi = context), kept in rbx.
  The index table `0x65096c0` is loaded into r13 at `0x636b957`, and
  its first entry is loaded into rsi at `0x636b971`.
- Exits: one ret at `0x636ba87`, after a full epilogue
  (`add $0x1a8,%rsp` + pops) and the canary check. No jump leaves the
  window (verified by program), so there is no tail-jump exit.
- Gate references (mechanism only): the size argument rdx is compared
  against `0x1000` at `0x636b975` (`ja 0x636ba90` into the size-class
  block); otherwise the threshold table `0x67277c0` is indexed by
  `(rdx + 7) >> 3` and the loaded byte is passed in rcx to the helper.
  There is no `0x23` threshold comparison in this FDE, and the
  `0x6713606` gate byte seen in #278/#279/#283/#284/#288/#289 is not
  referenced here. Node resolution uses the `0x6727a00` table indexed
  by `(value >> 0x30)`. Referenced tables `0x6727a00`, `0x6511a00`,
  `0x67277c0`, `0x65096c0` are .bss addresses; only the mechanism is
  reported, never runtime values.

## The walk (single shape, two null-context sites)

Top index: `(key >> 0x1a) & 0xf0` into the table at context + `0x1b0`;
the stored high bits (`key & 0xffffffffc0000000`) are compared against
the entry. On match, the second level is `(key >> 0x9) & 0x1ffff8`
added to the table's `+0x8` slot, yielding a node pointer. The node
value is then resolved through the `0x6727a00` table indexed by
`(value >> 0x30)`. On a top-level mismatch, the walk scans (below) and,
on a scan hit, inserts: it writes the new key and swaps the `0x100`/
`0x108` fields of the table entry.

Bin_table_init sites (both rdi = `lea 0x10(%rsp)`, each block the target
of exactly one `je` on a null-context test):

| site | block | branch | argument | rejoin |
| --- | --- | --- | --- | --- |
| `0x636baf8` | `0x636baf0` | test %rbp,%rbp; je from `0x636b9b7` | lea 0x10(%rsp) in r12 | mov %r12,%rsi; jmp `0x636b9bd` (walk restarts with stack-temp table) |
| `0x636bb5d` | `0x636bb50` | test %rbp,%rbp; je from `0x636ba11` | lea 0x10(%rsp) in rdx, saved at `0x8(%rsp)` | mov `0x8(%rsp)`,%rdx; jmp `0x636ba17` (second-level walk on stack-temp table) |

## The scans (8 slots, two shapes)

The scan array sits at walk-table + `0x100`, 16-byte entries, slot 0 the
MRU head. On a hit, the hit entry swaps into slot 0 (move-to-front).

- Scan 1 (first-walk mismatch, table in rsi): slot 0 at `0x636bb08`
  (`cmp 0x100(%rsi),%r15`), slot 1 at `0x636bc17`
  (`cmp 0x110(%rsi),%r15`), unrolled slots 2..7 at
  `0x636bcf8..0x636bd60` (`0x120..0x170`; reversed-operand form at
  `0x140` and `0x150`). Move-to-front at `0x636bb15` (slot 0) and
  `0x636bc24` (slot >= 1, rejoining the slot-0 sequence at `0x636bb1c`).
  Exhaustion falls to lu-miss `0x636bd81`.
- Scan 2 (second-walk mismatch, table in rdx): slot 0 at `0x636bb70`
  (`cmp 0x100(%rdx),%r15`), slot 1 at `0x636bbc8`
  (`cmp 0x110(%rdx),%r15`), unrolled slots 2..7 at
  `0x636bc5f..0x636bccd` (`0x120..0x170`; reversed-operand form at
  `0x120`, `0x130`, `0x140`). Move-to-front at `0x636bb79` (slot 0)
  and `0x636bbd5` (slot >= 1, rejoining the slot-0 sequence at
  `0x636bb80`). Exhaustion falls to lu-miss `0x636bcee`.

Lu-miss sites (both rsi = `lea 0x6511a00`, r8 = 1, r9 = 0):

| site | rdi | rdx | rcx | rejoin |
| --- | --- | --- | --- | --- |
| `0x636bcee` | rbp context | table (context + 0x1b0) | rbx key | jmp `0x636ba38` |
| `0x636bd81` | rbp context | rsi scan-1 table | rbx key | jmp `0x636b9f5` |

## Node resolution and the lock add

After the second-level match, the resolved value is field-extracted
(`shl/sar $0x10`, mask `$0xffffffffffffff80` at
`0x636ba3b..0x636ba43`), then used to index the `0x65096c0` table by
`(value & 0xfff)`, and the FDE executes `lock add %r14,0x38(%r13)` at
`0x636ba57` — a refcount increment during node resolution. This is a
`lock add`, not a `lock sub`: the lock-sub count in this FDE is 0,
unlike #285/#286/#287, which each carried one `lock sub` decrement.

## Size-class block (gate path only)

Reached when the size argument exceeds `0x1000` (`ja 0x636ba90`).
`movabs $0x7000000000000000,%rax`; if rdx exceeds that value
(`jb 0x636bbb8`), ecx is set to `0xe8` and control rejoins at
`0x636b996`. Otherwise: rcx = 2 * rdx - 1, r8 = rdx - 1, rbx = -1,
r9d = 6, `bsr %rcx,%rdi` at `0x636bab9` (the FDE's only `bsr`),
ecx = max(7, bsr) - 3, rbx = ((-1 << ecx) & (rdx - 1)) >> ecx,
ebx &= 3, r9d = max(6, bsr), ecx = -0x17 + ebx + 4 * r9d, then
`jmp 0x636b996` back to the helper call. The computed ecx replaces the
threshold-table byte as the helper's rcx argument.

## Raw-e8 ranking and the 2-raw tier

Raw 0xe8 census (byte scan of `.text` for e8 with rel32 target
`0x63d9880`, grouped by enclosing `.eh_frame` FDE from the readelf FDE
list of 135,313 FDEs; raw counts are an upper bound, site counts come
from objdump mnemonics; total 108, matching the established figure):
10 (#275), 8 (#276), 6 (#277), 6 (#278), 5 (#279), then 4-count FDEs
(#280–#287, exhausted), then 2-count FDEs: `0x6349780` (#288),
`0x6361320` (#289), and this FDE `0x636b940`. There is no 3-raw tier
at all (0 FDEs with exactly 3 raw sites). The remaining 2-raw
candidates are listed in the next question; the 1-raw tier has 17 FDEs.

## Cited, not claimed

- bin_table_init body `0x63d9880..0x63d9a64` (packet #262).
- lu-miss handler `0x63d9700..0x63d987b` (packet #215).
- Previous FDE `0x636b8f0..0x636b937`, next FDE `0x636bd90..0x636c49c`
  (packet #282's window, adjacent with padding 0).
- Helper `0x6364880` (returns the key; its body is not decoded here).
- Tables `0x6727a00`, `0x6511a00`, `0x67277c0`, `0x65096c0` (reads,
  not claims).

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_walk_10rsp_2sites.py`
  (byte reads only; never executes the binary): exit 0, 81 checks,
  including binary size + SHA-256, `.eh_frame` bounds, gap int3 bytes,
  exhibit bytes, strict recount (228), call census (6 total /
  2 bin_table_init / 2 lu-miss / 1 ret), bsr count (1), lock-sub
  count (0) with lock-add presence (1, at `0x636ba57`), branch shapes
  at both sites, canary checks, records consistency, `.rela.dyn`
  census (60,723 entries total, 59,534 RELATIVE, stated distinctly;
  `.rela.plt` 278 entries counted separately), disjointness, slug
  check, raw-e8 census and ranking, and MANIFEST digests.
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_walk_10rsp_2sites.py`:
  exit 0, 17 checks. Tamper controls first (hex flip, strict-count
  change, call-site change, injected overlap — each confirmed to fail
  the verifier; clean temp copy confirmed to pass), plus regeneration
  comparisons and independent strict/census recounts.
- `make verify`: exit 0 (559 evidence-packet manifests, 7159 entries =
  base 7154 + this packet's 5 MANIFEST entries).
- `make catalogue-check`: exit 2, pre-existing `Stale catalogue:
  README.md` on the new base — not a packet regression, and not claimed
  as passing.
- Full `make test` is NOT attempted: 584 test files on the new base
  take hours and risk a VM-restart kill mid-run; no full-suite tally is
  claimed.
- MANIFEST.sha256: all 5 entries verified with `sha256sum -c`.
- The `.hex` exhibit contains raw binary bytes, not hex text.

## Disjointness

The verifier's range-only collector scans the merged tree plus prior
worktree records and gathers string range fields, [start, end] lists,
and start/end pairs (including decimal-integer forms) inside
exhibits/windows lists or dicts or a dict literally named "window". It
never collects enclosing-fde annotation fields, census/cited-only
metadata subtrees, next-caller pointers, scan descriptors, or
control-flow edges. Self-exclusion is by exact window equality, never
by slug, so an injected overlapping range still fails the verifier.
Disjointness: NONE over prior ranges, 0 overlaps, 0 records skipped,
including packet #282's window `0x636bd90..0x636c49c` (adjacent, not
overlapping), packet #288's window `0x6349780..0x6349bd9`, packet
#289's window `0x6361320..0x63620da`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`. The slug
`RE-001-node115-lu-bintableinit-caller-2sites-walk-10rsp` does not
collide with any merged-tree directory.

## Not covered

- The remaining 2-raw candidates and the 1-raw tier (see next question).
- The bin_table_init / lu-miss handler / helper bodies.
- Runtime values of any `.bss` byte (mechanism only, never values).
- Packet #289's framings are NOT corrected or re-claimed here; its
  1104-byte pointer for this FDE is verified correct as described above.

## Next question

Build packet #291 on the next surviving 2-raw candidate
`0x63c89c0..0x63c8d5a` (922 bytes, 2 bin_table_init sites, 2 lu-miss
sites, 0 ret, 0 bsr), after re-verifying its site count and claim status
against prior exhibits. If that candidate fails verification, fall
through the surviving list in order: `0x63cd910..0x63cddce` (1214B,
2 bti, 2 miss, 1 ret, 1 bsr), `0x63d4171..0x63d4289` (280B, 2 bti,
0 miss, 0 ret, 0 bsr), `0x63d4289..0x63d4425` (412B, 2 bti, 0 miss,
1 ret, 0 bsr), `0x63d4497..0x63d463e` (423B, 2 bti, 0 miss, 1 ret,
0 bsr), `0x63d61a0..0x63d6575` (981B, 2 bti, 2 miss, 1 ret, 0 bsr),
`0x63ed8b0..0x63edf05` (1621B, 2 bti, 2 miss, 1 ret, 2 bsr). Excluded:
`0x63ed090..0x63ed862` (partially claimed by #260) and
`0x63ef8e0..0x63efba2` (partially claimed by #258) — not buildable as
whole FDEs.
