# RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp

Seventh bin_table_init caller FDE: the lookup walk at
0x63c8d60..0x63c94fc (1948 bytes, 411 strict lines, 14 calls,
0 ret), carrying over from packet #280's next question.
Unlike #275 (one stack temp, 10 sites), #276 (one register,
8 sites), #277 (mixed args, 6 sites), #279 (five walk
variants, 5 sites), and #280 (one stack temp 0x10(%rsp),
4 sites), this FDE runs a single radix walk plus an 8-slot
move-to-front scan, with four null-context bin_table_init
sites all using the same stack temp 0x0(%rsp) — plain rsp,
not a lea offset — and four lu-miss fallbacks. Unlike #278
(a dump routine with no walk and no lu-miss sites), this FDE
pairs the walk with the scan. Unlike #275/#276/#277/#279, it
has no size-class block (no bsr anywhere in the FDE); the
only threshold in the walk is a (value >> 0x30) vs 0x23 gate.
All exits are canary-checked tail-jumps; there is no ret.
Static analysis only; the target binary is never executed.

Target: node #115, artifacts/node/115/hl-node, 105,896,032
bytes, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
upstream main
05bc2de303c05525b71e7e257426e741bc66a390 (fetch-confirmed,
unmoved).

## Prior pointer verified (no correction)

Packet #280's records named this FDE "0x63c8d60..0x63c94fc"
with 1948 bytes and 4 raw candidates. Both figures are
verified correct: 0x63c94fc - 0x63c8d60 = 0x79c = 1948 bytes,
computed by program from the `.eh_frame` bounds (previous
FDE ends at 0x63c8d5a, next FDE starts at 0x63c9500), and the
objdump census finds exactly 4 bin_table_init sites. No #280
framing is corrected.

## The FDE

- Window: 0x63c8d60..0x63c94fc, 1948 bytes, 411 strict lines
  (address + bytes field + tab + mnemonic starting with a
  lowercase letter; byte-continuation lines excluded), 14
  calls, 0 ret.
- Frame 0x198, canary at 0x188(%rsp), canary checks at
  0x63c8ef0, 0x63c8f93, and 0x63c9101, each jumping to the
  `__stack_chk_fail` call at 0x63c94ca on mismatch. Entry
  starts with push %r15 (no endbr64).
- Bounds from `.eh_frame` (PC-relative sdata4, fixed 4-byte
  range fields, not ULEB), not from endbr64 scanning.
  Previous FDE 0x63c89c0..0x63c8d5a, gap before 6 bytes
  (0xcc int3 padding). Next FDE 0x63c9500..0x63c964d,
  padding after 4 bytes (0xcc).
- Entry: rdi = context (kept in rbx), rsi = flag struct
  (kept in r12), rdx = key (kept in rbp). Entry helper
  0x63d3a00 runs, then mutex 0x6714660 is unlocked and byte
  0x6714688 is cleared (mechanism references only; 0x6714660
  also appears in #275's mechanism description, which claims
  no bytes here). The flag block reads 0x71(%r12) and
  0x72(%r12) and calls helpers 0x63c3730 / 0x63c3990.
  Context-field clearing at 0x63c8de5 ((%rbp) context, byte
  0x68 cleared, +0x40 unlock).

## The walk (single shape, four null-context sites)

Top index: (key >> 0x1a) & 0xf0 into the walk table
(context + 0x1b0 on the first pass, the bti-initialized
stack table at rsp on later passes); the stored high bits
(key & 0xffffffffc0000000) are compared against the entry.
On match, the second level is (key >> 0x9) & 0x1ffff8 added
to the table's +0x8 slot, yielding a node pointer. The node
value is then resolved through the 0x6727a00 table indexed
by (value >> 0x30), and the 0x65096c0-table refcount is
decremented with a `lock sub` on the entry indexed by
(value & 0xfff) — the same tail shape as #278's phase tails
and #280's walk. On a top-level mismatch, the walk inserts:
it writes the new key and swaps the 0x100/0x108 fields of
the table entry. The high-bits gate at 0x63c8f40 compares
(value >> 0x30) against 0x23 (jbe 0x63c90f0); this is a
threshold gate, not a bsr size-class block.

## bin_table_init: 4 sites, one arg shape, all rbx == 0 branches

Every site is reached from a `test %rbx,%rbx` followed by
`je`: bin_table_init initializes a fresh bin table whenever
the walk finds no context (rbx == 0). bin_table_init itself
(0x63d9880..0x63d9a64) was claimed by packet #262; only its
caller FDE is claimed here. All four sites use the same
stack temp — plain rsp, unlike #280's lea 0x10(%rsp) and
#279's lea 0x20(%rsp).

| site | block | branch | argument | rejoin |
| ---- | ----- | ------ | -------- | ------ |
| 0x63c8fc6 | 0x63c8fc0 | test rbx,rbx; je from 0x63c8e00 | rdi = rsp | 0x63c8fcb |
| 0x63c9026 | 0x63c9020 | test rbx,rbx; je from 0x63c8e5a | rdi = rsp | 0x63c902b |
| 0x63c908e | 0x63c9088 | test rbx,rbx; je from 0x63c8eb2 | rdi = rsp | 0x63c9093 |
| 0x63c9296 | 0x63c9290 | test rbx,rbx; je from 0x63c8f58 | rdi = rsp | 0x63c929b |

Each site block is the target of exactly one `je`
(verified). Walk resumes: site 1 jumps to 0x63c8e06 (walk
restarts with table = rsp); site 2 re-does the lookup and
jumps to 0x63c8e70 on match; site 3 re-does the lookup and
jumps to 0x63c8ec8 on match; site 4 jumps to 0x63c8f5e
(walk with table = rsp).

## The 8-slot scan and the lu-miss fallbacks

Beside the radix walk, the FDE scans an 8-entry array at
walk-table + 0x100 with 16-byte entries. Slot 0 (base +
0x100) is the most-recently-used head. The insert path
checks the head slot, then scans slots 1..7 (base +
0x110..0x170); on a hit, the entry swaps into slot 0
(move-to-front). Three scans are unrolled; one is an
indexed loop (base r15 = rsp, index r11 from 1 while
r11 != 8). On exhaustion, each scan calls the lu-miss
handler (#215's FDE, cited not claimed) with the same
argument shape except for the table-base register:

| lu-miss site | scan | argument (rdx varies) | rejoin |
| ------------ | ---- | --------------------- | ------ |
| 0x63c9329 | unrolled, base r14 = rsp | rdx = r14 | 0x63c932e |
| 0x63c93b9 | unrolled, base r15 = walk table | rdx = r15 | 0x63c93be |
| 0x63c9449 | unrolled, base rsi = walk table | rdx = rsi | 0x63c944e |
| 0x63c94f2 | indexed loop at 0x63c9453, base r15 = rsp | rdx = r15 | 0x63c94f7 |

All four lu-miss calls share: rdi = rbx (context),
rsi = lea 0x6511a00, rcx = rbp (key), r8 = 1, r9 = 0. The
rejoin points resume the radix walk's second level, so a
miss does not abort the walk.

## Exits (0 ret)

All exits are canary-checked tail-jumps, as in #276 and
#280:

- First exit at 0x63c8f0d: canary check, pops, tail-jmp to
  helper 0x63637f0 (cited not claimed).
- Second exit at 0x63c8fb9: canary check, pops, tail-jmp to
  walk helper 0x63bd6c0 (cited not claimed).
- Third exit at 0x63c9125: canary check, pops, tail-jmp to
  helper 0x6363260 (cited not claimed).

## Other callees (context only, not claims)

- 0x63d3a00 x1: entry helper.
- 0x63f0b70 x2: pthread_mutex_unlock@plt.
- 0x63c3730 x1, 0x63c3990 x1: flag helpers.
- 0x63f0d70 x1: `__stack_chk_fail`@plt.

## Exhibits

`.hex` exhibits contain raw binary bytes, not hex text.
Coordinate mapping: `.text` file offset = VA - 0x1000;
`.rodata` = VA as-is; `.data` = VA - 0x3000.

| exhibit | range | bytes | strict |
| ------- | ----- | ----- | ------ |
| bintableinit_caller_walk_rsp_4sites | 0x63c8d60..0x63c94fc | 1948 | 411 |

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_walk_rsp_4sites.py`
  (byte reads only; never executes the binary): exit 0, 40
  checks, including binary size + SHA-256, `.eh_frame`
  bounds, gap/padding int3 bytes, exhibit bytes, strict
  recount (411), call census (14 total / 4 bin_table_init /
  4 lu-miss / 0 ret), rbx == 0 branch shape at all 4 sites,
  canary + `__stack_chk_fail` checks, no-bsr check, records
  consistency, `.rela.dyn` census (60,723 entries total,
  59,534 RELATIVE, stated distinctly), disjointness, slug
  check, raw-e8 census and ranking, and MANIFEST digests.
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_walk_rsp_4sites.py`:
  11/11 pass, tamper controls first (hex flip,
  strict-count change, call-site list change, injected
  overlap — each confirmed to fail the verifier; clean temp
  copy confirmed to pass), plus regeneration comparisons
  and independent strict/census recounts.
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
  5 (#279), 4 (#280), 4 (this FDE), 4 (six others). This
  FDE's raw count (4) equals its objdump-verified site
  count (4).

## Disjointness

The verifier's range-only collector scans the merged tree
plus prior worktree records and gathers string range fields,
[start, end] lists, and start/end pairs inside
exhibits/windows lists or dicts or a dict literally named
"window". It never collects enclosing-fde annotation fields,
census/cited-only metadata subtrees, next-caller pointers,
scan descriptors, or control-flow edges. The window is
disjoint from every prior claimed range, including packet
#232's merged FDE 0x63b8820..0x63b8d85, packet #252's
r28_wait window 0x63ec890..0x63ec8a3, packet #215's handler
FDE 0x63d9700..0x63d987b, packet #261's group-36 tcache
window 0x63721c0..0x6372246, packet #261's opt_prof window
0x63737c0..0x6373846, packet #262's prof_prefix,
prof_active, and lg_prof_sample windows, packet #262's
bin_table_init window 0x63d9880..0x63d9a64, packet #269's
xmalloc window 0x6378090..0x637809a, packet #261's
0x634ebb0..0x634eccd window, packet #275's caller FDE
0x63cba10..0x63ccd22, packet #276's caller FDE
0x63c9c80..0x63cb146, packet #277's caller FDE
0x63ce8c0..0x63cf8bc, packet #278's caller FDE
0x63d4bbe..0x63d5428, packet #279's caller FDE
0x63bd8c0..0x63be4ce, and packet #280's caller FDE
0x63cb150..0x63cba04. The slug
RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp does
not collide with any merged-tree directory.

## Not covered

- The remaining 107 static leaves, unchanged by this packet.
- The callee FDEs' internals beyond their call-site argument
  patterns.
- Runtime values of the `.bss` addresses (mutex, gate byte,
  tables) — only the mechanism is reported.
- Whether the four walk paths correspond to four distinct
  callers or one caller inlined four times: observed control
  flow only, not proven.
- The next bin_table_init caller FDE 0x636bd90..0x636c49c
  (4 raw candidates, 1804 bytes, verified unclaimed): not
  decoded. Five other 4-raw FDEs also remain (0x6350210,
  0x6365660, 0x63d3080, 0x63d5940, 0x63ec900); the chain
  continues from 0x636bd90.
- Packet #280's framings are NOT corrected or re-claimed
  here; its 1948-byte pointer for this FDE is verified
  correct as described above.

## Next question

Decode the next bin_table_init caller FDE 0x636bd90..0x636c49c
(4 raw candidates, 1804 bytes).
