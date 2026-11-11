# RE-001: lu bin_table_init walk caller, 5 sites

Fifth bin_table_init caller FDE: the five-variant lookup walk at
0x63bd8c0..0x63be4ce (3086 bytes, 661 strict lines, 23 calls, 1 ret),
carrying over from packet #278's next question. Unlike #275 (one stack
temp, 10 sites), #276 (one register, 8 sites), and #277 (mixed args,
6 sites), this FDE runs five parallel radix-walk variants that share
one epilogue, each variant carrying its own null-context
bin_table_init site, all five using the same stack temp 0x20(%rsp).
Unlike #278 (a dump routine with no walk and no lu-miss sites), this
FDE is a lookup walk with a full 8-slot move-to-front scan and five
lu-miss fallbacks. Static analysis only; the target binary is never
executed.

## The FDE

- Window: 0x63bd8c0..0x63be4ce, 3086 bytes, 661 strict lines
  (address + bytes field + tab + mnemonic starting with a lowercase
  letter; byte-continuation lines excluded), 23 calls, 1 ret at
  0x63bdad2.
- Frame 0x1b8, canary at 0x1a8(%rsp), single canary check at
  0x63bdaa7, `__stack_chk_fail` call at 0x63be258. Entry starts with
  endbr64.
- Bounds from `.eh_frame` (PC-relative sdata4, fixed 4-byte range
  fields, not ULEB), not from endbr64 scanning. Previous FDE
  0x63bd6c0..0x63bd8b5, gap before 11 bytes (0xcc int3 padding).
  Next FDE 0x63be4d0..0x63be53d, padding after 2 bytes (0xcc).
- Entry: rdi = context (kept in r15), rdx = key (kept in r12),
  rcx = third argument (kept in rbp), r9b = flag byte (kept in r11b).
  If rdi == 0, the entry bin_table_init site runs first (below).
- The `.bss` gate byte 0x6713606 is checked twice (0x63bda45,
  0x63bdc28; cmpb $0x0, jne to an alternate walk variant). It is a
  byte read, not a range claim; the same byte gated #278's entry.
- Packet #278's next-question pointer named this FDE with 3086
  bytes and 5 raw candidates. Both figures are verified correct:
  0x63be4ce - 0x63bd8c0 = 0xc0e = 3086 by program arithmetic from
  the `.eh_frame` bounds, and the objdump census finds exactly 5
  bin_table_init sites. No #278 framing is corrected.

## The walk (shared shape, five variants)

Top index: (key >> 0x1a) & 0xf0 into the table at context + 0x1b0;
the stored high bits (key & 0xffffffffc0000000) are compared against
the entry. On match, the second level is (key >> 0x9) & 0x1ffff8
added to the table's +0x8 slot, yielding a node pointer. On a
top-level mismatch, the walk inserts: it writes the new key and
swaps the 0x100/0x108 fields of the table entry (for example at
0x63bdbe0 and 0x63bde50).

The five variants differ only in register allocation and re-entry
point; each re-enters the walk after its own null-context site:

| variant | walk entry | table register | null-context site | rejoin |
| ------- | ---------- | -------------- | ----------------- | ------ |
| 1 (entry) | 0x63bd922 | rbx | 0x63bdbcd | 0x63bd922 |
| 2 | 0x63bdae8 | rbx | 0x63bdea5 | 0x63bdae8 |
| 3 | 0x63bdce0 | rbp | 0x63bdf68 | 0x63bdce0 |
| 4 | 0x63bddb9 | r13 | 0x63be099 | 0x63bddb9 |
| 5 | 0x63bdc6d | rbp | 0x63be24a | 0x63bdc6d |

Variant 1 continues past the lookup helper 0x63bd2e0 (called with
the 0x6727a00 table) into a copy helper 0x63bcd20 and a memcpy,
then the size-class path. Variant 4's second level calls the walk
helper 0x63bd6c0, which is the previous FDE itself (cited, not
claimed). All variants converge on the shared epilogue at
0x63bdaa7 (canary check, pops, ret with rax = r10).

Size-class block (two copies, at 0x63bde21 and 0x63bdf9a): bsr of
(size - 1), class clamped to 6..7, index -0x17 + 4 * class + low
2 bits, a 0x23 threshold byte read from the 0x67277c0 table, and
0x1000 and 0x7000000000000000 size thresholds. The same block
shape appeared in #275/#276/#277.

## bin_table_init: 5 sites, one arg shape, all null-context branches

Every site is reached from a null-context branch: the entry site
from `test %rdi,%rdi` followed by `je`, the other four from
`test %r15,%r15` followed by `je`. bin_table_init initializes a
fresh bin table whenever the walk finds no context. bin_table_init
itself (0x63d9880..0x63d9a64) was claimed by packet #262; only its
caller FDE is claimed here. All five sites pass the same stack
temp, unlike #275 (one stack temp across 10 sites), #276 (one
register across 8 sites), #277 (mixed shapes), and #278 (mixed
shapes in a dump routine).

| site | block | branch | argument | rejoin |
| ---- | ----- | ------ | -------- | ------ |
| 0x63bdbcd | 0x63bdbc0 | entry test rdi,rdi; je | rdi = lea 0x20(%rsp) | 0x63bd922 |
| 0x63bdea5 | 0x63bde98 | test r15,r15; je | rdi = lea 0x20(%rsp) | 0x63bdae8 |
| 0x63bdf68 | 0x63bdf5c | test r15,r15; je | rdi = lea 0x20(%rsp) | 0x63bdce0 |
| 0x63be099 | 0x63be08d | test r15,r15; je | rdi = lea 0x20(%rsp) | 0x63bddb9 |
| 0x63be24a | 0x63be23e | test r15,r15; je | rdi = lea 0x20(%rsp) | 0x63bdc6d |

## The 8-slot scan and the lu-miss fallbacks

Beside the radix walk, the FDE scans an 8-entry array at
context + 0x100 with 16-byte entries. Slot 0 (0x100) is the
most-recently-used head: it is never compared. Scans compare
slots 1..7 (0x110..0x170); on a hit, the entry swaps into slot 0
(move-to-front). Two scans are unrolled (slots 2..7 written out
after slot 1 is checked separately); three are indexed loops
(esi from 1 while esi != 8). On exhaustion, each scan calls the
lu-miss handler (#215's FDE, cited not claimed) with the same
argument shape except for the table-base register:

| lu-miss site | scan | argument (rdx varies) | rejoin |
| ------------ | ---- | --------------------- | ------ |
| 0x63be1ee | unrolled, after 0x63bdeb8 | rdx = rbx | 0x63bd959 |
| 0x63be362 | unrolled, after 0x63be0a7 | rdx = rbx | 0x63bdb21 |
| 0x63be44e | indexed loop at 0x63be25d | rdx = r13 | 0x63bdca8 |
| 0x63be487 | indexed loop at 0x63be371 | rdx = rbp | 0x63bdd16 |
| 0x63be4c0 | indexed loop at 0x63be3d4 | rdx = rbp | 0x63bdca8 |

All five lu-miss calls share: rdi = r15 (context),
rsi = lea 0x6511a00, rcx = r12 (key), r8 = 1, r9 = 0. The
rejoin points resume the radix walk's second level, so a miss
does not abort the walk.

## Other callees (context only, not claims)

- 0x63bd2e0 x1: lookup helper (0x6727a00 table).
- 0x63bcd20 x1: copy helper.
- 0x63b7240 x1, 0x63b73a0 x1: byte/word transform helpers
  (lengths 8 - flag and 4 - flag).
- 0x63f0a60 x1: memcpy@plt.
- 0x63b7500 x1: fill helper on the miss path (flag inverted).
- 0x63bd6c0 x1: walk helper, the previous FDE (cited, not
  claimed).
- 0x63637f0 x1: size-class helper.
- 0x63ead50 x1: table helper (0x64ffdcc shift table).
- 0x6363260 x2: indexed helper, ecx = 1.
- 0x63eb870 x1: table helper (0x64ffdc8 shift table).
- 0x63f0d70 x1: `__stack_chk_fail`@plt.

## Exhibits

`.hex` exhibits contain raw binary bytes, not hex text.
Coordinate mapping: `.text` file offset = VA - 0x1000;
`.rodata` = VA as-is; `.data` = VA - 0x3000.

| exhibit | range | bytes | strict |
| ------- | ----- | ----- | ------ |
| bintableinit_caller_walk_5sites | 0x63bd8c0..0x63be4ce | 3086 | 661 |

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_walk_5sites.py`
  (byte reads only; never executes the binary): exit 0, 40
  checks, including binary size + SHA-256, `.eh_frame`
  bounds, exhibit bytes, strict recount (661), call census
  (23 total / 5 bin_table_init / 5 lu-miss / 1 ret),
  null-context branch shape at all 5 sites, records
  consistency, `.rela.dyn` census (60,723 entries total,
  59,534 RELATIVE, stated distinctly), disjointness, slug
  check, raw-e8 census and ranking, and MANIFEST digests.
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_walk_5sites.py`:
  9/9 pass, tamper controls first (hex flip, strict-count
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
  5 (this FDE), 4 (eight FDEs, including 0x63cb150..0x63cba04).
  This FDE's raw count (5) equals its objdump-verified site
  count (5).

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
0x63ce8c0..0x63cf8bc, and packet #278's caller FDE
0x63d4bbe..0x63d5428. The slug
RE-001-node115-lu-bintableinit-caller-5sites-walk does not
collide with any merged-tree directory.

## Not covered

- The remaining 107 static leaves, unchanged by this packet.
- The callee FDEs' internals beyond their call-site argument
  patterns.
- Runtime values of the `.bss` addresses (gate byte, tables)
  — only the mechanism is reported.
- Whether the five walk variants correspond to five distinct
  callers or one caller inlined five times: observed control
  flow only, not proven.
- The next bin_table_init caller FDE 0x63cb150..0x63cba04
  (4 raw candidates): not decoded. Seven other 4-raw FDEs
  also remain (0x6350210, 0x6365660, 0x636bd90, 0x63c8d60,
  0x63d3080, 0x63d5940, 0x63ec900); the chain continues from
  0x63cb150 per packet #277's pointer, verified unclaimed.
- Packet #278's framings are NOT corrected or re-claimed
  here; its 3086-byte pointer for this FDE is verified
  correct as described above.

## Next question

Decode the next bin_table_init caller FDE 0x63cb150..0x63cba04
(4 raw candidates, 2228 bytes).
