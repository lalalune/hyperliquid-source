# RE-001: lu opt groups 61-64 leaves

Node-115-only light packet: the final four control-tree leaves of the
opt node's children array, in tree order after packet #273's groups
56–60 leaves (opt/prof_sys_thread_name, opt/prof_time_resolution,
opt/lg_san_uaf_align, opt/zero_realloc), all read-only in effect.
This packet takes packet #273's first next-question option only; the
largest bin_table_init caller FDE 0x63cba10 (10 sites) is explicitly
NOT decoded here, per #273's "pick one, not both".

## Why four leaves, not five

The opt children array (0x64de2e0, 65 children, 5-qword entries,
handler slot at entry offset +32) ends at group 64. The entry one
slot past the array, 0x64ded08, is not a node entry: it has no
name-slot (+0x08) relocation, and its +0x20 slot resolves via
`.rela.dyn` to 0x43fce3, a `.rodata` address, not a `.text`
handler. Groups 61–64 are therefore the last four opt children,
and this packet classifies all of them. A handler-start
containment check over all prior exhibits finds every group 0–15
handler covered by a prior claim, and groups 16–60 were classified
by the #266–#273 chain, so the opt-children census (65 children,
indices 0–64) is complete with this packet. No fifth opt leaf
exists to pad the batch with, and none is fabricated.

## Leaves (4 of the 111 remaining at packet start)

All handlers except the stub are reached only by dispatcher
indirect tail-call: a whole-`.text` E8 census gives 0 direct
entries per leaf. Each handler's node+0x20 slot was confirmed
via `.rela.dyn` addends (60,723 `.rela.dyn` entries total,
59,534 of type RELATIVE; file slots are zero-filled, so the
addend is the authority), and each node+0x08 name addend
resolves to the leaf name below. FDE bounds come from
`.eh_frame` (PC-relative sdata4 encoding, fixed 4-byte range
fields — not ULEB, per packet #270's lesson), not from endbr64
scanning.

Tree order is node order, not address order (packet #267's
lesson): here they disagree again — group 63's handler
(0x6378080) sits far above groups 61, 62, and 64 in address
order, while group 64's handler (0x63747e0) follows group 62's.
Group 61's handler (0x6374540) is exactly packet #273's
next-question FDE, verified unclaimed before building.

This batch is mixed-shape like packets #266/#267/#268/#270/
#271/#272/#273, not one template: one plain-byte leaf, two
indirect-table u64 leaves, and one constant-return stub. The
three non-stub leaves share the same contract skeleton (the
same shape as packet #261's value leaves): a write attempt
(newp|newlen != 0) returns 1 without touching memory; a read
with oldp==0 or oldlenp==0 returns 0; a read with
*oldlenp==size stores the value and returns 0; any other
*oldlenp takes the short-read path (n = min(*oldlenp, size)
bytes copied from a stack temp, *oldlenp set to n, return
0x16). Single ret per FDE; all jumps stay inside the FDE;
the only out-of-FDE transfer in the non-stub FDEs is the
`__stack_chk_fail` call on canary mismatch.

| leaf | node | handler FDE | value | file value |
| ---- | ---- | ----------- | ----- | ---------- |
| opt/prof_sys_thread_name | 0x64dec68 | 0x6374540..0x63745c6 | byte at .bss 0x67125f0 | runtime (not in file) |
| opt/prof_time_resolution | 0x64dec90 | 0x63745d0..0x63747dd | qword from .data table 0x64ffca0 indexed by u32 at .bss 0x6712370 | table file-known, index runtime |
| opt/lg_san_uaf_align | 0x64decb8 | 0x6378080..0x637808a | constant return 2 | 2 |
| opt/zero_realloc | 0x64dece0 | 0x63747e0..0x63749ed | qword from .data table 0x64ffb40 indexed by u32 at .data 0x64ffb58 | index 1, selected entry 0 |

File-initial values only: `.data` is writable, so runtime
values may differ; `.bss` values are not in the file at all.
The two indirect-table leaves are instruction-identical
modulo the value-load lea displacements and intra-FDE jump
targets (verified by a normalized instruction-level diff,
149 lines each). Their short-read path is a memcpy-style
unrolled 8-byte copy loop, which is why they are 525 bytes
rather than the 535 bytes of the plain-u64 leaves.

Observed address relationships, not proven struct claims:
prof_time_resolution's index slot (`.bss` 0x6712370) sits
8 bytes below packet #271's thp index slot (`.bss`
0x6712378), and its table (`.data` 0x64ffca0) sits 32 bytes
below thp's table (`.data` 0x64ffcc0). zero_realloc's index
slot (`.data` 0x64ffb58) is table base + 0x18, i.e. the low
half of table entry 3, whose full file qword is
0x100000001 — consistent with the file-initial index value
1. Whether any of these slots belong to one struct or one
table is NOT proven and is left open. The indirect-table
file contents that are known: prof_time_resolution's table
opens [0, 0, 0x1ffffffff, 0]; zero_realloc's table opens
[0, 0, 0, 0x100000001, 0, 0x800000, 0x800000, 0x2710].
After this packet, 107 of the 204 static leaves remain
unclassified.

## Exhibits (4 windows, 1194 bytes, 337 strict lines)

Strict = address + bytes field + tab + mnemonic starting with a
lowercase letter; objdump byte-continuation lines excluded.
`.hex` exhibits contain raw binary bytes, not hex text.

| exhibit | range | bytes | strict |
| ------- | ----- | ----- | ------ |
| prof_sys_thread_name | 0x6374540..0x63745c6 | 134 | 36 |
| prof_time_resolution | 0x63745d0..0x63747dd | 525 | 149 |
| lg_san_uaf_align | 0x6378080..0x637808a | 10 | 3 |
| zero_realloc | 0x63747e0..0x63749ed | 525 | 149 |

Paddings to the next FDE: prof_sys_thread_name →
prof_time_resolution 10 bytes; prof_time_resolution →
zero_realloc 3 bytes; lg_san_uaf_align → xmalloc (claimed by
#269) 6 bytes; zero_realloc → thread_allocated (claimed by
#261) 3 bytes. The lg_san_uaf_align stub bytes
(f30f1efab802000000c3: endbr64 + `mov $0x2,%eax` + ret)
are byte-identical to packet #269's xmalloc stub.

## Verification

- Static verifier `tools/node115_lu_opt_groups61_64_leaves.py`
  (byte reads only; never executes the binary): exit 0.
- Own unit tests `tests/test_node115_lu_opt_groups61_64_leaves.py`:
  standalone, 7/7 pass, including regeneration comparison,
  independent strict recount, and tamper controls run first
  (hex flip, strict-count change, injected overlap,
  value-slot lea change — each confirmed to fail the
  verifier, and a clean temp copy confirmed to pass).
- `make verify`: exit 0 (559 evidence-packet manifests, 7167
  entries — actual tally: base 7154 + this packet's 13 MANIFEST
  entries).
- `make catalogue-check`: exit 2, pre-existing `Stale catalogue:
  README.md` on the new base (verified: no catalogue file is
  touched by this packet; only the packet dir, tools file, and
  tests file are added) — not a packet regression, and not
  claimed as passing.
- Full `make test` is NOT attempted: 584 test files on the new
  base take hours and risk a VM-restart kill mid-run; no
  full-suite tally is claimed.
- MANIFEST.sha256 verified with `sha256sum -c` (all 13 entries
  OK).

## Disjointness

The verifier's collector scans the merged tree plus prior
worktree records (#183–#273), deduplicated by real packet slug,
and gathers ONLY exhibited windows: string range fields,
[start, end] lists (hex strings or int pairs), and start/end
pairs inside exhibits lists or dicts, and windows lists or
dicts. It never collects enclosing-fde annotation fields
(packet #259 lesson) and never collects census/cited-only
metadata subtrees (packet #253 lesson). All 4 windows are
disjoint from every prior claimed range (1062 unique-slug
ranges), from packet #232's merged FDE
`0x63b8820..0x63b8d85` (checked explicitly), from packet
#252's r28_wait window `0x63ec890..0x63ec8a3`, from packet
#215's handler FDE `0x63d9700..0x63d987b`, from packet
#261's group-36 tcache window `0x63721c0..0x6372246`, from
packet #261's opt_prof window `0x63737c0..0x6373846`, from
packet #261's thread_allocated window
`0x63749f0..0x6374bfa`, from packet #262's prof_prefix,
prof_active, and lg_prof_sample windows, from packet #269's
xmalloc window `0x6378090..0x637809a`, and from each other.
The slug `RE-001-node115-lu-opt-groups61-64-leaves` does not
collide with any merged-tree directory. Group 61's handler
(0x6374540) is exactly packet #273's next-question FDE,
verified unclaimed before building (packet #270's lesson: a
pointer is not a claim of availability).

## Not covered (explicit)

- The remaining 107 static leaves, which now live entirely
  outside the opt children array.
- The getter family and dispatcher internals beyond the leaf
  contract.
- Runtime values of the `.bss` byte at 0x67125f0, the
  `.bss` index u32 at 0x6712370, and the runtime values of
  the `.data` slots at 0x64ffca0 and 0x64ffb40/0x64ffb58
  (only file-initial values are reported).
- Whether the adjacent index/table slots belong to one
  struct or one table: observed address proximity only, not
  proven.
- The largest bin_table_init caller FDE 0x63cba10 (10 sites):
  not decoded (packet #273's other option, explicitly not
  taken here).
- Packet #273's framings are NOT corrected or re-claimed
  here; nothing in this packet's disassembly contradicts
  #273's classified leaves.

## Next question

The opt children array is exhausted, so the next packet must
open a new family. Decode the largest bin_table_init caller
FDE 0x63cba10 (10 sites); or open the next leaf family
outside opt children. Packet #275 should pick one of these,
not both, to stay light — and, per the #270/#272 lessons,
must verify every address in its window against prior
exhibits before building, not just the first FDE.
