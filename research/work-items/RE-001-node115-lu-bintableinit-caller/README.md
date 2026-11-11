# RE-001: lu bin_table_init caller, 10 sites

Node-115-only light packet: the bin_table_init caller FDE
0x63cba10..0x63ccd22 (4882 bytes, 1015 strict lines), the first
next-question option of packet #274. The opt children array is
exhausted at group 64 (#274), so this packet classifies no leaf;
the 107 static leaves remaining at packet start are unchanged.
The largest bin_table_init caller FDE 0x63cba10 (10 sites) is
decoded here; the next-largest caller and the next leaf family
outside opt children are left for packet #276 ("pick one, not
both").

## Pointer clarification (not a correction)

Packet #274's pointer named this FDE "the largest bin_table_init
caller FDE 0x63cba10 (10 sites)". The FDE identity and the site
count (10) are confirmed, but "largest" needs one qualification:
it means most call sites, not most bytes. A raw-e8 census over
all `.eh_frame` FDE ranges, grouped by enclosing FDE, finds this
FDE with 10 candidates for target 0x63d9880 and no other caller
FDE above 8 raw candidates; since a raw count is an upper bound
on real calls, no other caller can exceed 8 real sites, while
this FDE's 10 are verified by objdump mnemonic. By byte size,
the next caller 0x63c9c80..0x63cb146 (5318 bytes) is larger
than this FDE (4882 bytes). No classified leaf or prior framing
is corrected here.

## The FDE (1 window, 4882 bytes, 1015 strict lines)

FDE bounds come from `.eh_frame` (PC-relative sdata4 encoding,
fixed 4-byte range fields — not ULEB, per packet #270's lesson),
not from endbr64 scanning. The FDE opens with six pushes, a
0x1f8-byte frame, and a stack canary at 0x1e8(%rsp). There is
exactly one `ret` (0x63cbd80), reached through a single canary
check; the only out-of-FDE transfer on canary mismatch is the
`__stack_chk_fail` call at 0x63cc9e9. Total calls: 49.

Entry contract (from register use, not from symbols — the
binary's symbol names are stripped to a single base label):
rdi (rbx) is a context struct whose +0x1b0 slot is the radix
root array; rsi (r12) is a key-descriptor struct whose +0x0 is
a record base and whose +0x8 is a u32 index; rdx (rbp) is a
flags struct with bytes at +0x70/+0x71/+0x72; rcx/r8/r9 are
spilled at entry and restored as out-params at exit. The exit
block returns r13d: the main path zeroes it first (return 0),
while early exits preserve the lookup-helper code.

## Mutex gate (3 trylock sites, 4 unlock sites)

One global mutex cluster in `.bss` (runtime values, not in the
file): mutex 0x6714660, counter 0x6714658, owner 0x6714650, miss
counter 0x6714648, flag byte 0x6714688. The pattern is identical
at all three trylock sites (0x63cba5c, 0x63cbc81, and the
per-node lock at 0x63cbd99, which locks [r13+0x40] instead):
trylock; on failure call the lock-wait helper 0x63bf680 (itself
claimed by packet #251's wait-helper records — cited here, not
claimed), set flag byte 0x6714688 to 1, and retry. On success,
increment counter 0x6714658; if the owner slot 0x6714650 differs
from rbx, increment miss counter 0x6714648 and store rbx as the
new owner. Every unlock site (0x63cbac8, 0x63cbd00, 0x63cbdd3,
0x63cc11e) first clears flag byte 0x6714688 to 0.

## Radix walk skeleton

Key offset r14 = 0x78 + 8 * [r12+0x8]. If r14 exceeds 0x1000,
the bsr size-class block at 0x63cc458 computes an index (bsr
on 2*r14-1, clamped to 6, plus a 2-bit remainder, yielding
ecx = -0x17 + 4*clamped + remainder) and rejoins at 0x63cbb35.
Otherwise the walk reads the first qword of the table pointer
at 0x65096c0 (a runtime `.bss`-region address; its contents are
not in the file); if that qword is 0, the empty-table path
calls 0x634ebb0 with (0, 0x64da4b0) and rejoins at 0x63cbb16
(0x634ebb0 itself was packet #261's substitute topic — cited
here, not claimed). A bitmap byte is read from the runtime
`.bss` bitmap at 0x67277c0 + (r14 >> 3), and the node-fetch
helper 0x6364880 is called with (rbx, table-base first qword,
r14, bitmap byte, 0); a 0 result takes the early exit.

Each walk instance then repeats the same shape: top index
(key >> 0x1a) & 0xf0 selects a slot at rbx+0x1b0 + top; the
slot's tag must equal key & 0xffffffffc0000000; the second
level is (key >> 9) & 0x1ffff8 added to slot+8; the leaf value
is decoded as (leaf >> 0x10 sign-extended) & ~0x7f, and
(leaf & 0xfff) indexes the table at 0x65096c0; the second
`.bss` table at 0x6727a00 is indexed by leaf >> 0x30. Leaf
records carry a refcount adjusted with `lock add`/`lock sub`
on struct+0x38. A leaf whose low bit is set takes the
0x63637f0 helper path (2 sites); a leaf whose value >> 0x30
exceeds 0x23 takes a deeper walk, otherwise the 0x6363260
(2 sites) or 0x63bd6c0 (2 sites) helper path. Tag mismatches
at any level splice a new node into the 16-byte-entry arrays
(see below) instead of failing.

## bin_table_init: 10 sites, one stack temp

All 10 call sites pass exactly one argument: rdi = lea
0x60(%rsp), the same stack temp inside the 0x1f8 frame.
0x60(%rsp) is referenced exactly 10 times in the whole FDE,
all of them that lea. Each site sits in a distinct
empty-slot / null-node branch of the walk (four of them are
the rbx == 0 branches at 0x63cc15e, 0x63cc1b8, 0x63cc210, and
0x63cc5c0; the rest are walk-miss branches), and after the
call the initialized temp is carried in a different register
to a distinct rejoin point. So bin_table_init initializes a
fresh bin table in the caller's stack temp whenever the walk
finds no existing node — 10 separate miss branches across
the walk's phases, not one loop. bin_table_init itself
(0x63d9880..0x63d9a64) was claimed by packet #262 (PR #2810);
only its caller FDE is claimed here.

| site | rejoin | branch kind |
| ---- | ------ | ----------- |
| 0x63cbf88 | 0x63cbdf1 | walk-miss branch |
| 0x63cc080 | 0x63cbea4 | walk-miss branch |
| 0x63cc0e5 | 0x63cbe4b | walk-miss branch |
| 0x63cc37d | 0x63cbb5f | walk-miss branch |
| 0x63cc3ef | 0x63cbbbe | walk-miss branch |
| 0x63cc503 | 0x63cbfee | rbx == 0 branch |
| 0x63cc691 | 0x63cc164 | rbx == 0 branch |
| 0x63cc6ab | 0x63cc1be | rbx == 0 branch |
| 0x63cc705 | 0x63cc216 | walk-miss branch |
| 0x63ccbdc | 0x63cc5c6 | rbx == 0 branch |

## lu-miss handler: 10 sites, one arg pattern

All 10 call sites to the lu-miss handler 0x63d9700 (packet
#215's handler FDE — cited here, not claimed) share one
argument pattern: rdi = rbx, rsi = 0x6511a00, rdx = node,
rcx = key, r8 = 1, r9 = 0. The rsi value 0x6511a00 lies in
the `.bss` region, so it is a runtime buffer address, not a
file string; its contents are not claimed. Five sites follow
unrolled 7-slot scans (slots at node+0x110..node+0x170,
16-byte stride, key in each slot's first qword) and five
follow indexed loops (counter 1..8 over node+0x100 + 16*i).
On a slot match, control jumps to a shared splice block
(0x63cc27b, 0x63cc2de, 0x63cc32d, 0x63cc51f, 0x63cc56d) that
shifts 16-byte (key, value) pairs and inserts at the matched
position; on a full miss, the handler is called and control
rejoins the walk. The miss sites are 0x63cc79b, 0x63cc8ab,
0x63cc93b, 0x63cc9d5, 0x63cca71 (unrolled scans) and
0x63ccc10, 0x63ccc41, 0x63ccc72, 0x63ccca3, 0x63ccd18
(indexed loops).

## Flags protocol (3 occurrences)

At entry, if rdx != 0, byte [rdx+0x70] is set to 1. At each
of the three unlock/exit points, if rbp != 0, bytes
[rbp+0x71] and [rbp+0x72] are read, [rbp+0x72] is cleared to
0 and the word [rbp+0x70] is cleared to 0; then helper
0x63c3990 is called with rbx if +0x71 was set, and helper
0x63c3730 is called with rbx if +0x72 was set. The helpers'
internals are not decoded here (context, not claims).

## Other callees (context only, not claims)

- 0x63d3aa0 (2 sites): lookup helper, args (0x67144c0
  table, r12, out-param stack slots); result in r13d/r12d,
  0 means the failure path.
- 0x63d39a0 (1 site): second-phase helper, args (rbx, r15,
  r14, r14+0x68); a nonzero result takes the unlock path.
- 0x6364880 (1 site): node fetch, described above.
- 0x63637f0 (2 sites): low-bit-set leaf path, args (rbx, key).
- 0x6363260 (2 sites): small-value path, args (rbx, key, 0, 1).
- 0x63bd6c0 (2 sites): leaf follow-up, args (rbx,
  leaf-derived value).
- memcpy (1 site): record fill into r14+0x78.
- pthread_mutex_trylock (3 sites), pthread_mutex_unlock
  (4 sites), `__stack_chk_fail` (1 site): as described above.

## Exhibits (1 window, 4882 bytes, 1015 strict lines)

Strict = address + bytes field + tab + mnemonic starting with a
lowercase letter; objdump byte-continuation lines excluded.
`.hex` exhibits contain raw binary bytes, not hex text.

| exhibit | range | bytes | strict |
| ------- | ----- | ----- | ------ |
| bintableinit_caller | 0x63cba10..0x63ccd22 | 4882 | 1015 |

Padding to the next FDE: the next FDE starts at 0x63ccd30
(verified from `.eh_frame`), so the padding is 14 bytes.
The previous FDE ends at 0x63cba04 (the FDE at
0x63cb150..0x63cba04, itself a bin_table_init caller with 4
raw candidates), so the gap before this FDE is 12 bytes.

## Verification

- Static verifier `tools/node115_lu_bintableinit_caller.py`
  (byte reads only; never executes the binary): exit 0.
- Own unit tests `tests/test_node115_lu_bintableinit_caller.py`:
  standalone, 9/9 pass, including regeneration comparison,
  independent strict recount, and tamper controls run first
  (hex flip, strict-count change, call-site list change,
  injected overlap — each confirmed to fail the verifier,
  and a clean temp copy confirmed to pass).
- `make verify`: exit 0 (559 evidence-packet manifests, 7161
  entries — actual tally: base 7154 + this packet's 7 MANIFEST
  entries).
- `make catalogue-check`: exit 2, pre-existing `Stale catalogue:
  README.md` on the new base (verified: no catalogue file is
  touched by this packet; only the packet dir, tools file, and
  tests file are added) — not a packet regression, and not
  claimed as passing.
- Full `make test` is NOT attempted: 584 test files on the new
  base take hours and risk a VM-restart kill mid-run; no
  full-suite tally is claimed.
- MANIFEST.sha256 verified with `sha256sum -c` (all 7 entries
  OK).

## Disjointness

The verifier's collector scans the merged tree plus prior
worktree records (#183–#274), deduplicated by real packet slug,
and gathers ONLY exhibited windows: string range fields,
[start, end] lists (hex strings or int pairs), and start/end
pairs inside exhibits lists or dicts, and windows lists or
dicts. It never collects enclosing-fde annotation fields
(packet #259 lesson) and never collects census/cited-only
metadata subtrees (packet #253 lesson). The window is disjoint
from every prior claimed range, from packet #232's merged FDE
`0x63b8820..0x63b8d85` (checked explicitly), from packet
#252's r28_wait window `0x63ec890..0x63ec8a3`, from packet
#215's handler FDE `0x63d9700..0x63d987b`, from packet
#261's group-36 tcache window `0x63721c0..0x6372246`, from
packet #261's opt_prof window `0x63737c0..0x6373846`, from
packet #261's thread_allocated window
`0x63749f0..0x6374bfa`, from packet #262's prof_prefix,
prof_active, and lg_prof_sample windows, from packet #262's
bin_table_init window `0x63d9880..0x63d9a64`, from packet
#269's xmalloc window `0x6378090..0x637809a`, and from packet
#261's `0x634ebb0..0x634eccd` window. The slug
`RE-001-node115-lu-bintableinit-caller` does not collide with
any merged-tree directory.

## Not covered (explicit)

- The remaining 107 static leaves, unchanged by this packet.
- The callee FDEs' internals beyond their call-site argument
  patterns (see above).
- Runtime values of the `.bss` addresses (0x65096c0 table
  pointer, 0x67277c0 bitmap, 0x6727a00 table, 0x6511a00 miss
  buffer, the 0x67144c0/0x6714620/0x6714648/0x6714650/
  0x6714658/0x6714660/0x6714688 mutex cluster, 0x67144f8/
  0x6714500) — only the mechanism is reported.
- Whether the radix root at rbx+0x1b0 belongs to one named
  structure: observed walk shape only, not proven.
- The next-largest bin_table_init caller FDE 0x63c9c80
  (8 sites): not decoded.
- Packet #274's framings are NOT corrected or re-claimed
  here, except for the "largest" wording clarified above;
  nothing in this packet's disassembly contradicts #274's
  classified leaves.

## Next question

Decode the next-largest bin_table_init caller FDE 0x63c9c80
(8 sites); or open the next leaf family outside opt children.
Packet #276 should pick one of these, not both, to stay light
— and, per the #270/#272 lessons, must verify every address
in its window against prior exhibits before building, not
just the first FDE.
