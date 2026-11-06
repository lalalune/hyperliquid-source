# RE-001: lu bin_table_init caller, 8 sites

Node-115-only light packet: the second bin_table_init caller FDE
0x63c9c80..0x63cb146 (5318 bytes, 1179 strict lines), the first
next-question option of packet #275. The opt children array is
exhausted at group 64 (#274), so this packet classifies no leaf;
the 107 static leaves remaining at packet start are unchanged.
The next caller after #275's 10-site FDE, and the next leaf
family outside opt children, are left for packet #277 ("pick
one, not both").

## Why "second" is exact (sites, not bytes)

Packet #275's pointer named this FDE "the next-largest
bin_table_init caller FDE 0x63c9c80 (8 sites)". The FDE identity
and the site count (8) are confirmed, and "second-largest" is
exact by call sites: a raw-e8 census over all `.eh_frame` FDE
ranges for target 0x63d9880 finds #275's FDE with 10 raw
candidates, this FDE with 8, and no other FDE above 6. Since a
raw count is an upper bound on real calls, no other caller can
exceed 6 real sites, while this FDE's 8 are verified by objdump
mnemonic. By byte size this FDE (5318 bytes) is larger than
#275's FDE (4882 bytes) — the ranking is by sites, not bytes
(the #275 lesson: state superlatives precisely). No classified
leaf or prior framing is corrected here.

## The FDE (1 window, 5318 bytes, 1179 strict lines, 21 calls)

FDE bounds come from `.eh_frame` (PC-relative sdata4 encoding,
fixed 4-byte range fields — not ULEB, per packet #270's lesson),
not from endbr64 scanning. The FDE opens with six pushes, a
0x838-byte frame, and a stack canary at 0x828(%rsp). It contains
no `ret` at all: all three exits are canary-checked epilogues
(0x63ca274, 0x63ca45f, 0x63caa73 — each `sub %fs:0x28,%rax`
followed by `jne 0x63cb0e5`, the shared `__stack_chk_fail`
call) that restore the frame (`add $0x838,%rsp`, six pops) and
tail-jump to helpers (0x63637f0, 0x63bd6c0, 0x6363260), which
return directly to this function's caller. Total calls: 21.

Entry contract (from register use, not from symbols — the
binary's symbol names are stripped to a single base label):
rdi (rbp) is a context struct whose +0x1b0 slot is the radix
root array; rsi (rbx) is a key-descriptor struct whose +0x8
u32 is compared in the list phase, whose +0x18 is the radix
key, and whose +0x40 is passed to helper 0x63d3080. At entry
the global pointer at .bss-region address 0x67144a0 (runtime
value, not in the file) is loaded into the stack temp at
0x20(%rsp) and stored back at the walk exits; the temp's
address (r12) is the bin_table_init argument at every site.

## List phase (sorted-list merge)

Before any radix walk, the FDE merges a sorted list: it walks
nodes through 0x30 next pointers whose low bit is a tag
(cleared with `and $0xfffffffffffffffe` before dereference),
compares 64-bit keys with the setb/sbb idiom on 0x8 fields,
and splices nodes by rewriting 0x28 prev / 0x30 next fields,
with movups merges of adjacent fields. A stack array of
16-byte entries is walked downward by 0x10 toward r12 (the
0x20(%rsp) temp base). The empty-list path (global pointer
0 at entry) jumps to 0x63ca874, which re-establishes r12 as
the temp and rejoins the merge loop.

## Radix walk skeleton (same shape as #275)

After the list phase the walk repeats #275's skeleton twice
(phase 1 with the +0x18 key, phase 2 with rbx as key, joined
by a call to 0x63d3080 with (rdi = rbp, rsi = rbx+0x40)):
top index (key >> 0x1a) & 0xf0 selects a slot at rbp+0x1b0 +
top; the slot's tag must equal key & 0xffffffffc0000000;
the second level is (key >> 9) & 0x1ffff8 added to slot+8;
the leaf value is decoded as (leaf >> 0x10 sign-extended)
& ~0x7f, and (leaf & 0xfff) indexes the table at 0x65096c0
(a runtime .bss-region address); the second .bss table at
0x6727a00 is indexed by leaf >> 0x30. Leaf records carry a
refcount adjusted with `lock sub` on struct+0x38 (2 sites).
A leaf whose low bit is set takes the 0x63637f0 tail-jump
epilogue; a leaf whose value >> 0x30 exceeds 0x23 takes a
deeper walk, otherwise the 0x6363260 (call + tail jump) or
0x63bd6c0 (call + tail jump) helper path. Tag mismatches at
any level splice a new node into the 16-byte-entry arrays
(see below) instead of failing.

## bin_table_init: 8 sites, one register, all rbp == 0 branches

All 8 call sites pass exactly one argument: rdi = r12, and
every site is reached from an rbp == 0 branch (a `test %rbp`
followed by `je` to the site block) — bin_table_init
initializes a fresh bin table in the caller's temp when the
walk finds no context. r12 is the 0x20(%rsp) stack temp on
the main paths; site 0x63caaf5 is additionally reachable
from a slot-mismatch branch (0x63ca43e `jne`) where r12
holds a radix slot value instead. After each call the
spilled walk registers are restored and control rejoins
the walk at a distinct point. bin_table_init itself
(0x63d9880..0x63d9a64) was claimed by packet #262 (PR #2810);
only its caller FDE is claimed here.

| site | rejoin | branch kind |
| ---- | ------ | ----------- |
| 0x63ca4e1 | 0x63ca241 | rbp == 0 branch |
| 0x63ca53a | 0x63ca1f0 | rbp == 0 branch |
| 0x63ca592 | 0x63ca19d | rbp == 0 branch |
| 0x63ca666 | 0x63ca0ee | rbp == 0 branch |
| 0x63ca768 | 0x63ca14b | rbp == 0 branch |
| 0x63ca7c7 | 0x63ca08f | rbp == 0 branch |
| 0x63caaf5 | 0x63ca434 | rbp == 0 branch, or slot-mismatch branch |
| 0x63cabfd | 0x63ca6de | rbp == 0 branch |

## lu-miss handler: 8 sites, one arg pattern

All 8 call sites to the lu-miss handler 0x63d9700 (packet
#215's handler FDE — cited here, not claimed) share one
argument pattern: rdi = rbp, rsi = 0x6511a00, rdx = node,
rcx = key, r8 = 1, r9 = 0. The rsi value 0x6511a00 lies in
the `.bss` region, so it is a runtime buffer address, not a
file string; its contents are not claimed. Six sites follow
unrolled 7-slot scans (slots at node+0x110..node+0x170,
16-byte stride, index 2..7 tested in order) and two follow
indexed loops (counter 1..8 over node+0x100 + 16*i). On a
slot match, control jumps to a shared splice block that
shifts 16-byte (key, value) pairs and inserts at the matched
position; on a full miss, the handler is called and control
rejoins the walk. Six sites follow unrolled scans (0x63caf86,
0x63cb009, 0x63cb03b, 0x63cb06d, 0x63cb0a4, 0x63cb0d6) and two
follow indexed loops (0x63cb10e, 0x63cb13c).

## Other callees (context only, not claims)

- 0x63d3080 (1 site): phase-join helper, args (rbp,
  rbx+0x40); internals not decoded.
- 0x63637f0 (1 call, 1 tail jump): low-bit-set leaf path.
- 0x63bd6c0 (1 call, 1 tail jump): leaf follow-up path.
- 0x6363260 (1 call, 1 tail jump): small-value path.
- `__stack_chk_fail` (1 site): shared canary-fail target.

## Exhibits (1 window, 5318 bytes, 1179 strict lines)

Strict = address + bytes field + tab + mnemonic starting with a
lowercase letter; objdump byte-continuation lines excluded.
`.hex` exhibits contain raw binary bytes, not hex text.

| exhibit | range | bytes | strict |
| ------- | ----- | ----- | ------ |
| bintableinit_caller_8sites | 0x63c9c80..0x63cb146 | 5318 | 1179 |

Padding to the next FDE: the next FDE starts at 0x63cb150
(verified from `.eh_frame`), so the padding is 10 bytes.
The previous FDE ends exactly at 0x63c9c80 (the FDE at
0x63c9650..0x63c9c80), so the gap before this FDE is 0.

## Verification

- Static verifier `tools/node115_lu_bintableinit_caller_8sites.py`
  (byte reads only; never executes the binary): exit 0.
- Own unit tests `tests/test_node115_lu_bintableinit_caller_8sites.py`:
  standalone, 9/9 pass, including regeneration comparison,
  independent strict recount, independent call census, and
  tamper controls run first (hex flip, strict-count change,
  call-site list change, injected overlap — each confirmed
  to fail the verifier, and a clean temp copy confirmed to
  pass).
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
worktree records (#183–#275), deduplicated by real packet slug,
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
packet #262's prof_prefix, prof_active, and lg_prof_sample
windows, from packet #262's bin_table_init window
`0x63d9880..0x63d9a64`, from packet #269's xmalloc window
`0x6378090..0x637809a`, from packet #261's `0x634ebb0..0x634eccd`
window, and from packet #275's caller FDE
`0x63cba10..0x63ccd22`. The slug
`RE-001-node115-lu-bintableinit-caller-8sites` does not
collide with any merged-tree directory.

## Not covered (explicit)

- The remaining 107 static leaves, unchanged by this packet.
- The callee FDEs' internals beyond their call-site argument
  patterns (see above).
- Runtime values of the `.bss` addresses (0x67144a0 pointer,
  0x65096c0 table pointer, 0x6727a00 table, 0x6511a00 miss
  buffer) — only the mechanism is reported.
- Whether the radix root at rbp+0x1b0 belongs to one named
  structure: observed walk shape only, not proven.
- The next bin_table_init caller FDE 0x63ce8c0 (6 raw
  candidates): not decoded.
- Packet #275's framings are NOT corrected or re-claimed
  here; nothing in this packet's disassembly contradicts
  #275's classified caller FDE.

## Next question

Decode the next bin_table_init caller FDE 0x63ce8c0 (6 raw
candidates); or open the next leaf family outside opt children.
Packet #277 should pick one of these, not both, to stay light
— and, per the #270/#272 lessons, must verify every address
in its window against prior exhibits before building, not
just the first FDE.
