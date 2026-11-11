# RE-001-node115-lu-bintableinit-caller-2sites-walk-60rsp

Second 2-raw bin_table_init caller packet: FDE `0x6361320..0x63620da`
(3514 bytes, 737 strict lines, 42 calls, 0 ret), carrying over from packet
#288's next question. This is a small packet by design: 2 sites, not a
4-site walk. It is reported as such, not inflated.

Unlike the #275–#288 walkers, which are pure lookup walks on a
context+0x1b0 table, this FDE embeds its two bin_table_init sites in a
larger mutex-guarded routine with three parts: a phase-1 walk on the
context+0x1b0 table (no bin_table_init call), a drain sweep over a
360-entry table, and a stack-temp walk on a table at `lea 0x60(%rsp)`
that carries both bin_table_init sites. The single exit is a
canary-checked tail-jump; there is no ret, no bsr, and no lock sub.

Base: upstream main `05bc2de303c05525b71e7e257426e741bc66a390`
(fetch-confirmed at build time). Target binary
`artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Static analysis only; the target binary is never executed.

## Prior pointer verified (no correction)

Packet #288's survey pointer for this window (3514 bytes, 2
bin_table_init sites, 4 lu-miss sites, 0 ret, 0 bsr) is verified correct
by program arithmetic from the `.eh_frame` bounds (previous FDE ends at
`0x636131a` with a 6-byte `0xcc` gap, next FDE starts at `0x63620e0`
with a 6-byte `0xcc` padding) and by the objdump census below. No #288
framing is corrected.

## The FDE

- Window: `0x6361320..0x63620da`, 3514 bytes, 737 strict lines
  (address + bytes field + tab + mnemonic starting with a lowercase
  letter; byte-continuation lines excluded), 42 calls, 0 ret.
- Frame: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx, `sub $0x1f8,%rsp`,
  canary at `0x1e8(%rsp)`, one canary check at `0x6361750..0x6361761`
  (`sub %fs:0x28,%rax`, `jne` to the `__stack_chk_fail` call at
  `0x6361c74`).
- Entry: rsi = owner struct (kept in r15), rdi = context (kept in rbx,
  saved at `0x38(%rsp)`), key = `0x8(%rbp)` where rbp = `0x2920(%r15)`
  — the +0x8 field of the struct at entry-rsi's +0x2920 field. Key high
  bits `key & 0xffffffffc0000000`, masked key
  `key & 0xfffffffffffff000`. Mutexes: rsi+0x2968 (kept in r13) and
  rsi+0x2928 (saved at `0x8(%rsp)`). Every trylock failure goes through
  the lock-wait helper `0x63bf680` and retries: 7 trylock, 7 unlock,
  7 wait-helper calls.
- Exits: no ret. One tail-jump exit at `0x6361784` to `0x63bffe0`,
  after a full epilogue (`add $0x1f8,%rsp` + pops) and the canary
  check. No other jump leaves the window (verified by program).
  Exit-ness is per-FDE: `0x63bd6c0` is an ordinary returning call here
  (at `0x636143f` and `0x6361a72`), although it was a tail-jump exit in
  packet #288's FDE.
- Gate references (mechanism only): the byte at `0x6713606`,
  compared at `0x6361425` (phase-1) and `0x6361a56` (stack walk). Node
  resolution uses the `0x6727a00` table indexed by `(value >> 0x30)`.
  Referenced tables `0x6727a00`, `0x6511a00`, `0x6511780`,
  `0x6711b40`, `0x650969c` are .bss addresses; only the mechanism is
  reported, never runtime values.

## Part 1: phase-1 walk (context+0x1b0 table, no bin_table_init call)

Table `lea 0x1b0(%rbx)` in r12. Top index `(key >> 0x1a) & 0xf0`,
stored high bits compared against the entry. On match, the second level
is `(key >> 0x9) & 0x1ffff8` added to the table's `+0x8` slot, yielding
a node pointer. Node resolution reads the `0x6727a00` table by
`(value >> 0x30)`, then calls `0x63be4d0` (and `0x63c3330` when the
out-count exceeds 1), and finally the ordinary call to `0x63bd6c0`
(rdi = rbx context, rsi = rbp chain head) at `0x636143f`, after which
the walk loops (trylock, counters, rbp reload) until the chain head is
null, when control falls to the drain sweep.

On a top-level mismatch, the walk scans context fields: `0x2b0`
(insert — writes the new key and swaps the `0x2b0`/`0x2b8` fields,
then rejoins the second level at `0x6361422`), then `0x2c0`, `0x2d0`,
`0x2e0`, `0x2f0`, `0x300`, `0x310`, `0x320` (7 scan slots) with
move-to-front at `0x63619a3` and exhaustion to lu-miss `0x6361de8`.
On a node-resolution mismatch, the same fields are scanned again with
move-to-front at `0x6361c91` and exhaustion to lu-miss `0x6361edc`
(rejoin `0x6361947`).

## Part 2: drain sweep (360-entry table)

Outer table at `0x6711b40`: entries at +0x14 step 0x28 to +0x5b4
(360 entries), with a parallel u32 array at `0x6511780` (step 4 per
outer iteration, held in `0x28(%rsp)`). Each entry's count drives an
inner loop over 0xe0-stride records from base r15 + [u32]. Per record:
mutex at record+0x40 via trylock with `0x63bf680` wait-retry, counter
updates at +0x38/+0x30/+0x28 (same last-key pattern as the entry
counters), callback `0x63c0340` on the 0xc0 chain head and on 0xd8 list
nodes, `0x63ac480` on the 0xc8 chain, a doubly-linked-list splice at
`0x6361789` (unlinking the 0xd8 node, gated by the version check
`0x650969c` vs `0x13450(%r15)` at `0x6361650`), and fields 0xc0/0xd8/
0x88/0xb0 cleared. The sweep's purpose is described from this
field-clearing + callback pattern, not from runtime observation.

## Part 3: stack-temp walk (2 bin_table_init sites)

Reached when the entry context is null, and again after the `0x63bd6c0`
call path when the chain head is non-null. Both sites pass
rdi = `lea 0x60(%rsp)` (stack temp, kept in r14) — the same single-temp
shape as #283 (`lea 0x120(%rsp)`) and #284 (`lea 0x60(%rsp)`), but here
the two sites sit in different phases of the walk.

Bin_table_init sites:

| site | block | branch | argument | rejoin |
| --- | --- | --- | --- | --- |
| `0x6361a28` | `0x63619e7` | je from `0x63613be` on null entry rdi (also jne from `0x6361ab3` on non-null chain head, to `0x63619f5`) | lea 0x60(%rsp) | fall-through to slot read `0x6361a2d` |
| `0x6361c06` | `0x6361bef` | je from `0x6361a67` on node-value low bit 0 | lea 0x60(%rsp) | fall-through to slot read `0x6361c0b` |

Top index `(key >> 0x1e) & 0xf`, slot stride 16; stored high bits
compared against the slot. On match, the second level is
`(key >> 0x9) & 0x1ffff8` added to the slot's `+0x8` field. Node
resolution reads the `0x6727a00` table by `(value >> 0x30)` and calls
bin_table_init site 2; the resolved value is field-extracted
(`shl/sar $0x10`, mask `$0xffffffffffffff80`) and passed to `0x63be4d0`
(and `0x63c3330` when the out-count exceeds 1), then control returns to
the `0x63bd6c0` call path at `0x6361a6d`. The gate byte `0x6713606`
is checked at `0x6361a56`: zero goes to the `0x63bd6c0` path, and a
set low bit in the node value does the same.

Scans (8 slots each, table+0x100 = stack `0x160..0x1d0` step 0x10,
move-to-front on a hit):

- Scan 1 (site-1 mismatch): slots at `0x160`, `0x170`, `0x180`,
  `0x190`, `0x1a0`, `0x1b0`, `0x1c0`, `0x1d0`; move-to-front at
  `0x6361b8a` / `0x6361b12`; exhaustion falls to lu-miss `0x636201d`.
- Scan 2 (site-2 mismatch): same 8 slots; move-to-front at
  `0x6361f3d`; exhaustion falls to lu-miss `0x63620d0`.

Lu-miss sites (all rsi = `lea 0x6511a00`, r8 = 1, r9 = 0):

| site | rdi | rdx | rcx | rejoin |
| --- | --- | --- | --- | --- |
| `0x6361de8` | rbx context | r12 context table | masked key | jmp `0x6361422` |
| `0x6361edc` | rbx context | r12 context table | masked key | jmp `0x6361947` |
| `0x636201d` | 0 | r14 stack table | r13 masked key | jmp `0x6361a53` |
| `0x63620d0` | 0 | r14 stack table | r13 masked key | jmp `0x6361c31` |

## Size-class blocks

None: 0 bsr instructions in this FDE, like #280/#281/#282/#285/#286/
#287/#288 and unlike #275/#276/#277/#279/#283/#284, which had
size-class blocks. The gate paths here use threshold comparisons, not
bsr.

## Raw-e8 ranking and the 2-raw tier

Raw 0xe8 census (byte scan of `.text` for e8 with rel32 target
`0x63d9880`, grouped by enclosing `.eh_frame` FDE from the readelf FDE
list of 135,313 FDEs; raw counts are an upper bound, site counts come
from objdump mnemonics; total 108, matching the established figure):
10 (#275), 8 (#276), 6 (#277), 6 (#278), 5 (#279), then 4-count FDEs
(#280–#287, exhausted), then 2-count FDEs: `0x6349780` (#288) and this
FDE `0x6361320`. There is no 3-raw tier at all (0 FDEs with exactly 3
raw sites). The remaining 2-raw candidates are listed in the next
question; the 1-raw tier has 17 FDEs.

## Cited, not claimed

- bin_table_init body `0x63d9880..0x63d9a64` (packet #262).
- lu-miss handler `0x63d9700..0x63d987b` (packet #215).
- Previous FDE `0x63612b0..0x636131a`, next FDE `0x63620e0..0x6362130`.
- Tail-jump target `0x63bffe0`.
- Lock-wait helper `0x63bf680` (packet #251).
- Ordinary call target `0x63bd6c0` (packet #279's caller FDE; here an
  ordinary call, not an exit).
- Drain callbacks `0x63c0340`, `0x63ac480`, `0x6360610`,
  `0x63be4d0`, `0x63c3330` (context only — their bodies are not decoded
  here).
- Tables `0x6727a00`, `0x6511a00`, `0x6511780`, `0x6711b40`,
  `0x650969c` (reads, not claims).

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_walk_60rsp_2sites.py`
  (byte reads only; never executes the binary): exit 0, 63 checks,
  including binary size + SHA-256, `.eh_frame` bounds, gap/padding int3
  bytes, exhibit bytes, strict recount (737), call census (42 total /
  2 bin_table_init / 4 lu-miss / 0 ret), bsr count (0), lock-sub
  presence (0), branch shapes at both sites, canary checks, records
  consistency, `.rela.dyn` census (60,723 entries total, 59,534
  RELATIVE, stated distinctly; `.rela.plt` 278 entries counted
  separately), disjointness, slug check, raw-e8 census and ranking, and
  MANIFEST digests.
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_walk_60rsp_2sites.py`:
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
including packet #288's window `0x6349780..0x6349bd9`, packet #215's
handler FDE `0x63d9700..0x63d987b`, and packet #262's bin_table_init
window `0x63d9880..0x63d9a64`. The slug
`RE-001-node115-lu-bintableinit-caller-2sites-walk-60rsp` does not
collide with any merged-tree directory.

## Not covered

- The remaining 2-raw candidates and the 1-raw tier (see next question).
- The bin_table_init / lu-miss handler / tail-jump target / drain
  callback bodies.
- Runtime values of any `.bss` byte (mechanism only, never values).
- The drain sweep's runtime purpose beyond its field-clearing +
  callback pattern.
- Packet #288's framings are NOT corrected or re-claimed here; its
  3514-byte pointer for this FDE is verified correct as described above.

## Next question

Build packet #290 on the next surviving 2-raw candidate
`0x636b940..0x636bd90` (1104 bytes, 2 bin_table_init sites, 2 lu-miss
sites, 1 ret, 1 bsr), after re-verifying its site count and claim status
against prior exhibits. If that candidate fails verification, fall
through the surviving list in order: `0x63c89c0..0x63c8d5a` (922B,
2 bti, 2 miss, 0 ret, 0 bsr), `0x63cd910..0x63cddce` (1214B, 2 bti,
2 miss, 1 ret, 1 bsr), `0x63d4171..0x63d4289` (280B, 2 bti, 0 miss,
0 ret, 0 bsr), `0x63d4289..0x63d4425` (412B, 2 bti, 0 miss, 1 ret,
0 bsr), `0x63d4497..0x63d463e` (423B, 2 bti, 0 miss, 1 ret, 0 bsr),
`0x63d61a0..0x63d6575` (981B, 2 bti, 2 miss, 1 ret, 0 bsr),
`0x63ed8b0..0x63edf05` (1621B, 2 bti, 2 miss, 1 ret, 2 bsr). Excluded:
`0x63ed090..0x63ed862` (partially claimed by #260) and
`0x63ef8e0..0x63efba2` (partially claimed by #258) — not buildable as
whole FDEs.
