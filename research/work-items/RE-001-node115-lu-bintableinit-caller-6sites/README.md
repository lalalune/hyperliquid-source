# RE-001-node115-lu-bintableinit-caller-6sites

Node-115-only light packet: the third bin_table_init caller FDE
0x63ce8c0..0x63cf8bc (4092 bytes, 882 strict lines, 22 calls,
1 ret), the first next-question option of packet #276. The opt
children array is exhausted at group 64 (#274), so this packet
classifies no leaf; the 107 static leaves remaining at packet
start are unchanged.

## Target

- Binary: `artifacts/node/115/hl-node`, 105,896,032 bytes,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: upstream main `05bc2de303c05525b71e7e257426e741bc66a390`.
- FDE bounds come from `.eh_frame` (PC-relative sdata4 encoding,
  fixed 4-byte range fields — not ULEB, per packet #270's lesson),
  not from endbr64 scanning.

## The FDE (1 window, 4092 bytes, 882 strict lines, 22 calls, 1 ret)

The FDE opens with six pushes, a 0x838-byte frame, and a stack
canary at 0x828(%rsp). There is exactly one `ret` (0x63cec83),
reached through a single canary check; the only out-of-FDE
transfer on canary mismatch is the `__stack_chk_fail` call at
0x63cf740. The exit block returns rbx. Total calls: 22.

Entry contract (from register use, not from symbols — the
binary's symbol names are stripped to a single base label):
rdi (rbp) is a context struct whose +0x1b0 slot is the radix
root array; rsi, rcx, rdx, r8 are spilled at entry (rdx to
(%rsp), r8d to 0xc(%rsp)); the key is carried in r15 through
the walk and scan phases.

## Node setup and mutex gate (1 trylock site, 1 unlock site)

Before the walk, a node at rbx is built (0x10/0x18/0x20/0x38
fields, counter from 0x67144f0) and helper 0x63d2a80 is called
with (rdi = rbp, rsi = rbx+0x40); a nonzero result jumps to
the walk at 0x63cef00, a zero result takes the mutex path.
One mutex cluster in `.bss` (runtime values, not in the file):
mutex 0x67145e0, counter 0x67145d8, owner 0x67145d0, miss
counter 0x67145c8, flag byte 0x6714608. On trylock success,
counter 0x67145d8 is incremented; if owner 0x67145d0 differs
from rbp, miss counter 0x67145c8 is incremented and rbp is
stored as the new owner. On trylock failure, the lock-wait
helper 0x63bf680 is called with 0x67145a0 (mutex − 0x40),
flag byte 0x6714608 is set to 1, and control rejoins the
success path at 0x63cea76. The single unlock site (0x63cec53)
stores rbp to global pointer 0x67144a0, clears flag byte
0x6714608 to 0, and unlocks mutex 0x67145e0. This mutex
address differs from packet #275's 0x6714660 cluster: each
caller FDE guards its own mutex.

## Radix walk skeleton (same shape as #275/#276)

The walk reads the first qword of the table pointer at
0x65096c0 (a runtime `.bss`-region address; its contents are
not in the file); if that qword is 0, the empty-table path
calls 0x634ebb0 with (0, 0x64da4b0) and rejoins at 0x63ce90b
(0x634ebb0 itself was packet #261's substitute topic — cited
here, not claimed). A bitmap byte is read from the runtime
`.bss` bitmap at 0x67277c0 + (offset >> 3), and the node-fetch
helper 0x6364880 is called with (rbp, table-base first qword,
0x4b8, bitmap byte, 0); a 0 result takes the early exit.

Each walk instance then repeats the same shape: top index
(key >> 0x1a) & 0xf0 selects a slot at rbp+0x1b0 + top; the
slot's tag must equal key & 0xffffffffc0000000; the second
level is (key >> 9) & 0x1ffff8 added to slot+8; the leaf value
is decoded as (leaf >> 0x10 sign-extended) & ~0x7f, and
(leaf & 0xfff) indexes the table at 0x65096c0; the second
`.bss` table at 0x6727a00 is indexed by leaf >> 0x30. Leaf
records carry a refcount adjusted with `lock add`/`lock sub`
on struct+0x38. A leaf whose low bit is set takes the
0x63637f0 helper path (1 site); a leaf whose value >> 0x30
exceeds 0x23 takes a deeper walk, otherwise the 0x6363260
(1 site) or 0x63bd6c0 (1 site) helper path. Tag mismatches
at any level splice a new node into the 16-byte-entry arrays
instead of failing. Unlike packet #275, no bsr size-class
block appears in this FDE.

## bin_table_init: 6 sites, one stack temp, all rbp == 0 branches

All 6 call sites pass exactly one argument: rdi = lea
0x20(%rsp), the same stack temp inside the 0x838 frame.
Every site is reached from an rbp == 0 branch (a
`test %rbp,%rbp` followed by `je` to the site block) —
bin_table_init initializes a fresh bin table in the caller's
stack temp whenever the walk finds no context. The 0x20(%rsp)
slot doubles as the global-pointer temp elsewhere in the
FDE (stored at 0x63ceaa9, loaded at 0x63ceab7 and 0x63cec38,
and re-established at 0x63cf1ae), so the temp-reference
count (10) is not the site count (6). bin_table_init itself
(0x63d9880..0x63d9a64) was claimed by packet #262 (PR #2810);
only its caller FDE is claimed here.

| site | rejoin | branch kind |
| ---- | ------ | ----------- |
| 0x63cf130 | 0x63cf135 | rbp == 0 branch |
| 0x63cf19a | 0x63cf19f | rbp == 0 branch |
| 0x63cf1c8 | 0x63cef10 | rbp == 0 branch |
| 0x63cf27a | 0x63cef53 | rbp == 0 branch |
| 0x63cf28c | 0x63cefac | rbp == 0 branch |
| 0x63cf3c0 | 0x63cf3c5 | rbp == 0 branch |

## lu-miss handler: 6 sites, one arg pattern

All 6 call sites to the lu-miss handler 0x63d9700 (packet
#215's handler FDE — cited here, not claimed) share one
argument pattern: rdi = rbp, rsi = 0x6511a00, rdx = node,
rcx = rbx (key), r8 = 1, r9 = 0. The rsi value 0x6511a00 lies
in the `.bss` region, so it is a runtime buffer address, not
a file string; its contents are not claimed. Five sites
follow unrolled scans (slots at node+0x120..node+0x170,
16-byte stride, indices 2..7 tested in order) and one follows
an indexed loop (counter 1..8 over node+0x100 + 16*i). On a
slot match, control jumps to a shared splice block
(0x63cf32e, 0x63cf37c, 0x63cf3df, 0x63cf442, 0x63cf502) that
shifts 16-byte (key, value) pairs and inserts at the matched
position; on a full miss, the handler is called and control
rejoins the walk. The miss sites are 0x63cf64e, 0x63cf676,
0x63cf7f9, 0x63cf88f, 0x63cf8b2 (unrolled scans) and
0x63cf7d6 (indexed loop).

## Other callees (context only, not claims)

- 0x6364880 (1 site): node fetch, described above.
- 0x63d2a80 (1 site): node-setup helper, args (rbp,
  rbx+0x40); a nonzero result takes the walk path.
- 0x63f17b0 (1 site): pthread_mutex_trylock@plt, mutex
  0x67145e0.
- 0x63f0b70 (1 site): pthread_mutex_unlock@plt, mutex
  0x67145e0.
- 0x63bf680 (1 site): lock-wait helper, arg 0x67145a0.
- 0x63637f0 (1 site): low-bit-set leaf path, args (rbp,
  rbx).
- 0x634ebb0 (1 site): empty-table path, args (0,
  0x64da4b0).
- 0x63bd6c0 (1 site): leaf follow-up, args (rbp,
  leaf-derived value).
- 0x6363260 (1 site): small-value path, args (rbp, rbx,
  1, 0).
- 0x63f0d70 (1 site): `__stack_chk_fail`@plt.

## Exhibits (1 window, 4092 bytes, 882 strict lines)

Strict = address + bytes field + tab + mnemonic starting with a
lowercase letter; objdump byte-continuation lines excluded.
`.hex` exhibits contain raw binary bytes, not hex text.

| exhibit | range | bytes | strict |
| ------- | ----- | ----- | ------ |
| bintableinit_caller_6sites | 0x63ce8c0..0x63cf8bc | 4092 | 882 |

Padding to the next FDE: the next FDE starts at 0x63cf8c0
(verified from `.eh_frame`), so the padding is 4 bytes.
The previous FDE ends at 0x63ce8b8 (the FDE at
0x63ce510..0x63ce8b8), so the gap before this FDE is 8 bytes.

## Verification

- Static verifier `tools/node115_lu_bintableinit_caller_6sites.py`
  (byte reads only; never executes the binary): exit 0.
- Own unit tests `tests/test_node115_lu_bintableinit_caller_6sites.py`:
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
worktree records (#183–#276), deduplicated by real packet slug,
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
`0x6378090..0x637809a`, from packet #261's
`0x634ebb0..0x634eccd` window, from packet #275's caller FDE
`0x63cba10..0x63ccd22`, and from packet #276's caller FDE
`0x63c9c80..0x63cb146`. The slug
`RE-001-node115-lu-bintableinit-caller-6sites` does not
collide with any merged-tree directory.

## Not covered (explicit)

- The remaining 107 static leaves, unchanged by this packet.
- The callee FDEs' internals beyond their call-site argument
  patterns (see above).
- Runtime values of the `.bss` addresses (0x65096c0 table
  pointer, 0x67277c0 bitmap, 0x6727a00 table, 0x6511a00 miss
  buffer, the 0x67144a0/0x67145c8/0x67145d0/0x67145d8/
  0x67145e0/0x6714608 mutex cluster, 0x67144f0) — only the
  mechanism is reported.
- Whether the radix root at rbp+0x1b0 belongs to one named
  structure: observed walk shape only, not proven.
- The next bin_table_init caller FDE 0x63d4bbe..0x63d5428
  (6 raw candidates): not decoded.
- Packet #276's framings are NOT corrected or re-claimed
  here; nothing in this packet's disassembly contradicts
  #276's classified caller FDE.

## Next question

Decode the next bin_table_init caller FDE 0x63d4bbe..0x63d5428
(6 raw candidates); or open the next leaf family outside opt
children. Packet #278 should pick one of these, not both, to
stay light — and, per the #270/#272 lessons, must verify
every address in its window against prior exhibits before
building, not just the first FDE.
