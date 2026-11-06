# RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp-ret

Seventh bin_table_init caller FDE: the lookup walk at
0x636bd90..0x636c49c (1804 bytes, 379 strict lines, 9 calls,
1 ret), carrying over from packet #281's next question.

## What it is

Unlike #275 (one stack temp, 10 sites), #276 (one register,
8 sites), #277 (mixed args, 6 sites), #279 (five walk variants,
5 sites), #280 (one stack temp 0x10(%rsp), 4 sites), and #281
(plain rsp, 4 sites, 0 ret), this FDE runs a single radix walk
plus an 8-slot move-to-front scan, with four null-context
bin_table_init sites all using plain rsp as the argument, and
four lu-miss fallbacks. Unlike #278 (a dump routine with no
walk and no lu-miss sites), this FDE pairs the walk with the
scan. Unlike #275/#276/#277/#279, it has no size-class block
(no bsr anywhere in the FDE); the only threshold in the walk
is a (value >> 0x30) vs 0x23 gate. Unlike #281, it has one ret
(on the early rsi == 0 path) and no observed `.bss` mechanism
references: no gate byte, mutex, or list-head reads appear in
this FDE. Static analysis only; the target binary is never
executed.

## Prior pointer verified (no correction)

Packet #281's records named this FDE "0x636bd90..0x636c49c"
with 1804 bytes and 4 raw candidates. Both figures are verified
correct: 0x636c49c - 0x636bd90 = 0x70c = 1804 bytes, computed
by program from the `.eh_frame` bounds (previous FDE ends
exactly at 0x636bd90, next FDE starts at 0x636c4a0), and the
objdump census finds exactly 4 bin_table_init sites. No #281
framing is corrected.

## The FDE

- Window: 0x636bd90..0x636c49c, 1804 bytes, 379 strict lines
  (address + bytes field + tab + mnemonic starting with a
  lowercase letter; byte-continuation lines excluded), 9
  calls, 1 ret at 0x636bf08.
- Frame 0x198, canary at 0x188(%rsp), canary checks jumping
  to the `__stack_chk_fail` call at 0x636c46a on mismatch.
  Entry starts with push %r15 (no endbr64).
- Bounds from `.eh_frame` (PC-relative sdata4, fixed 4-byte
  range fields, not ULEB), not from endbr64 scanning.
  Previous FDE 0x636b940..0x636bd90, gap before 0. Next FDE
  0x636c4a0..0x636c52c, padding after 4 bytes (0xcc).
- Entry: rdi = context (kept in rbp), rsi = key (kept in
  rbx). If rsi == 0, the function returns early (via
  0x636bee0, ret at 0x636bf08). No `.bss` reads appear in
  this FDE.

## The walk (single shape, four null-context sites)

Top index: (key >> 0x1a) & 0xf0 into the table at context +
0x1b0; the stored high bits (key & 0xffffffffc0000000) are
compared against the entry. On match, the second level is
(key >> 0x9) & 0x1ffff8 added to the table's +0x8 slot,
yielding a node pointer. The node value is then resolved
through the 0x6727a00 table indexed by (value >> 0x30), and
the 0x65096c0-table refcount is decremented with a `lock
sub` on the entry indexed by (value & 0xfff) — the same tail
shape as #278's phase tails and #280's walk. On a top-level
mismatch, the walk inserts: it writes the new key and swaps
the 0x100/0x108 fields of the table entry. The high-bits gate
at 0x636bf10 compares (value >> 0x30) against 0x23
(jbe 0x636c09f); this is a threshold gate, not a bsr
size-class block.

## bin_table_init: 4 sites, one arg shape, all null-context branches

Site 1 is reached from a `test %rdi,%rdi` followed by `je`;
sites 2-4 from `test %rbp,%rbp` followed by `je`:
bin_table_init initializes a fresh bin table whenever the walk
finds no context. bin_table_init itself (0x63d9880..0x63d9a64)
was claimed by packet #262; only its caller FDE is claimed
here. All four sites use plain rsp, like #281 — but unlike
#281, whose branches are all `test %rbx,%rbx`, here the first
branch tests rdi and the rest test rbp, and the entry
registers differ (rdi = context in rbp, rsi = key in rbx,
vs #281's rdi in rbx, rdx in rbp).

| site | block | branch | argument | rejoin |
| ---- | ----- | ------ | -------- | ------ |
| 0x636bf96 | 0x636bf90 | test rdi,rdi; je from 0x636bdcd | rdi = rsp (via r12) | 0x636bdd3 |
| 0x636bff6 | 0x636bff0 | test rbp,rbp; je from 0x636be27 | rdi = rsp (via r15) | 0x636be2d |
| 0x636c04e | 0x636c048 | test rbp,rbp; je from 0x636be7f | rdi = rsp (via r14) | 0x636be85 |
| 0x636c233 | 0x636c22d | test rbp,rbp; je from 0x636bf28 | rdi = rsp (via r15) | 0x636bf2e |

Each site block is the target of exactly one `je` (verified).

## The 8-slot scan and the lu-miss fallbacks

Beside the radix walk, the FDE scans an 8-entry array at
walk-table + 0x100 with 16-byte entries. Slot 0 (base +
0x100) is the most-recently-used head: it is never compared
in the unrolled scans (the indexed loop starts at slot 1).
Scans compare slots 1..7 (base + 0x110..0x170); on a hit,
the entry swaps into slot 0 (move-to-front). Three scans are
unrolled; one is an indexed loop (base r15, index r10 from 1
while r10 != 8). On exhaustion, each scan calls the lu-miss
handler (#215's FDE, cited not claimed) with the same
argument shape except for the table-base register:

| lu-miss site | scan | argument (rdx varies) | rejoin |
| ------------ | ---- | --------------------- | ------ |
| 0x636c2c9 | unrolled, base r14 | rdx = r14 | 0x636bea5 |
| 0x636c359 | unrolled, base r15 | rdx = r15 | 0x636be4d |
| 0x636c3e9 | unrolled, base rsi | rdx = rsi | 0x636be0b |
| 0x636c492 | indexed loop at 0x636c3f3, base r15 | rdx = r15 | 0x636bf4f |

All four lu-miss calls share: rdi = rbp (context),
rsi = lea 0x6511a00, rcx = rbx (key), r8 = 1, r9 = 0. The
rejoin points resume the radix walk's second level, so a
miss does not abort the walk.

## Exits (1 ret + 3 canary-checked tail-jumps)

- Ret at 0x636bf08: the early rsi == 0 path (via 0x636bee0).
- Shared epilogue at 0x636beac: canary check, pops, tail-jmp
  to helper 0x63637f0 (cited not claimed).
- Second epilogue at 0x636bf69: canary check, pops, tail-jmp
  to walk helper 0x63bd6c0 (cited not claimed).
- Third epilogue at 0x636c09f: canary check, pops, tail-jmp
  to helper 0x6363260 (cited not claimed).

## Other callees (context only, not claims)

- 0x63637f0 x1, 0x63bd6c0 x1, 0x6363260 x1: tail-jump
  targets (cited, not claimed).
- 0x63f0d70 x1: `__stack_chk_fail`@plt.

## Exhibits

`.hex` exhibits contain raw binary bytes, not hex text.
Coordinate mapping: `.text` file offset = VA - 0x1000;
`.rodata` = VA as-is; `.data` = VA - 0x3000.

| exhibit | range | bytes | strict |
| ------- | ----- | ----- | ------ |
| bintableinit_caller_walk_rsp_ret_4sites | 0x636bd90..0x636c49c | 1804 | 379 |

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_walk_rsp_ret_4sites.py`
  (byte reads only; never executes the binary): exit 0, 53
  checks, including binary size + SHA-256, `.eh_frame`
  bounds, gap/padding int3 bytes, exhibit bytes, strict
  recount (379), call census (9 total / 4 bin_table_init /
  4 lu-miss / 1 ret), rdi/rbp == 0 branch shape at all 4
  sites, canary + `__stack_chk_fail` checks, no-bsr check,
  records consistency, `.rela.dyn` census (60,723 entries
  total, 59,534 RELATIVE, stated distinctly; `.rela.plt`
  278 entries counted separately), disjointness, slug
  check, raw-e8 census and ranking, and MANIFEST digests.
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_walk_rsp_ret_4sites.py`:
  12/12 pass, tamper controls first (hex flip, strict-count
  change, call-site list change, injected overlap — each
  confirmed to fail the verifier; clean temp copy confirmed
  to pass), plus regeneration comparisons and independent
  strict/census recounts.
- `make verify`: exit 0 (559 evidence-packet manifests, 7161
  entries = base 7154 + this packet's 7 MANIFEST entries).
- `make catalogue-check`: exit 2, pre-existing `Stale
  catalogue: README.md` on the new base — not a packet
  regression, and not claimed as passing.
- Full `make test` is NOT attempted: 584 test files on the
  new base take hours and risk a VM-restart kill mid-run; no
  full-suite tally is claimed.
- MANIFEST.sha256: all 7 entries verified with `sha256sum
  -c`.
- Raw-e8 census for target 0x63d9880 grouped by enclosing
  `.eh_frame` FDE: 10 (#275), 8 (#276), 6 (#277), 6 (#278),
  5 (#279), 4 (#280), 4 (#281), 4 (this FDE). This FDE's raw
  count (4) equals its objdump-verified site count (4).

## Disjointness

The verifier's range-only collector scans the merged tree
plus prior worktree records and gathers string range fields,
[start, end] lists, and start/end pairs inside
exhibits/windows lists or dicts or a dict literally named
"window". It never collects enclosing-fde annotation fields,
census/cited-only metadata subtrees, next-caller pointers,
scan descriptors, or control-flow edges. Self-exclusion is
by exact window equality, never by slug, so an injected
overlapping range still fails the verifier. The window is
disjoint from every prior claimed range, including packet
#275's caller FDE 0x63cba10..0x63ccd22, packet #276's caller
FDE 0x63c9c80..0x63cb146, packet #277's caller FDE
0x63ce8c0..0x63cf8bc, packet #278's caller FDE
0x63d4bbe..0x63d5428, packet #279's caller FDE
0x63bd8c0..0x63be4ce, packet #280's caller FDE
0x63cb150..0x63cba04, packet #281's caller FDE
0x63c8d60..0x63c94fc, packet #215's handler FDE
0x63d9700..0x63d987b, and packet #262's bin_table_init
window 0x63d9880..0x63d9a64. The slug
RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp-ret
does not collide with any merged-tree directory.

## Not covered

- The remaining 107 static leaves, unchanged by this packet.
- The callee FDEs' internals beyond their call-site argument
  patterns.
- Runtime values of the `.bss` addresses — none are
  referenced by this FDE, so nothing is claimed there.
- Whether the four walk paths correspond to four distinct
  callers or one caller inlined four times: observed control
  flow only, not proven.
- The next bin_table_init caller FDE 0x6350210..0x6352f5e
  (4 raw candidates, 11598 bytes, verified unclaimed): not
  decoded. Four other 4-raw FDEs also remain (0x6365660,
  0x63d3080, 0x63d5940, 0x63ec900); the chain continues from
  0x6350210.
- Packet #281's framings are NOT corrected or re-claimed
  here; its 1804-byte pointer for this FDE is verified
  correct as described above.

## Next question

Decode the next bin_table_init caller FDE 0x6350210..0x6352f5e
(4 raw candidates, 11598 bytes).
