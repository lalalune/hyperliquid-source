# RE-001-node115-lu-opt-groups37-41-leaves

Node-115-only light packet: five more control-tree leaves classified in tree
order after packet #269's five groups 31–35 leaves. This packet takes packet
#269's first next-question option only; the largest bin_table_init caller FDE
0x63cba10 (10 sites) is explicitly NOT decoded here, per #269's "pick one,
not both".

## Correction to packet #269's next question (group 36 already claimed)

Packet #269's next question named group 36 (opt/tcache, FDE 0x63721c0) as
the next group to classify. That pointer is wrong: packet #261 (PR #2804)
already classified opt/tcache — same node 0x64de880, same handler FDE
0x63721c0..0x6372246, same byte value at .data 0x64ffdf8, 134 bytes,
36 strict instructions. Re-claiming it would duplicate a submitted packet
(the packet #250 lesson: an assigned neighbour topic that turns out to be
already claimed must be dropped, not built on). Group 36 is therefore
skipped without re-claim, and this packet classifies groups 37–41 instead:
the four groups that follow it in tree order, plus group 41 as the fifth.
No group is skipped silently — the skip and its proof are stated here.

## Classified leaves (5 of the 131 remaining at packet start)

All five handlers are reached only by dispatcher indirect tail-call: a
whole-`.text` E8 census gives 0 direct entries per leaf. Each handler's
node+0x20 slot was confirmed via `.rela.dyn` addends (60,723 `.rela.dyn`
entries total, 59,534 of type RELATIVE; file slots are zero-filled, so the
addend is the authority), and each node+0x08 name addend resolves to the leaf
name below. The five are the opt node's children-array groups 37–41 (array
0x64de2e0, 65 children, 5-qword entries, handler slot at entry offset +32),
in tree order after packet #269's opt/experimental_infallible_new, with
group 36 skipped as already claimed (see above). FDE bounds come from
`.eh_frame` (PC-relative sdata4 encoding), not from endbr64 scanning.

Tree order is node order, not address order (packet #267's lesson): here
node order and address order happen to agree — group 37's handler
(0x6372250) is also the lowest address among the five.

This batch is mixed-shape like packets #266/#267/#268, not one template:
two plain-u64 leaves and three plain-u32 leaves. All five share the same
contract skeleton (the same shape as packet #261's value leaves): a write
attempt (newp|newlen != 0) returns 1 without touching memory; a read with
oldp==0 or oldlenp==0 returns 0; a read with *oldlenp==size stores the
value and returns 0; any other *oldlenp takes the short-read path (n =
min(*oldlenp, size) bytes copied from a stack temp, *oldlenp set to n,
return 0x16). Single ret per FDE; all jumps stay inside the FDE; the only
out-of-FDE transfer is the `__stack_chk_fail` call on canary mismatch. The
short-read copy differs by size: the u64 leaves copy through an unrolled
8-byte memcpy, the u32 leaves through a scalar byte loop — both from the
same stack-temp staging area the exact-length path uses.

| leaf | node | handler FDE | value | file value |
| ---- | ---- | ----------- | ----- | ---------- |
| opt/tcache_max | 0x64de8a8 | 0x6372250..0x6372467 | qword at .data 0x64ffdf0 | 0x8000 (32768) |
| opt/tcache_nslots_small_min | 0x64de8d0 | 0x6372470..0x6372623 | u32 at .data 0x64ffde8 | 0x14 (20) |
| opt/tcache_nslots_small_max | 0x64de8f8 | 0x6372630..0x63727e3 | u32 at .data 0x64ffde4 | 0xc8 (200) |
| opt/tcache_nslots_large | 0x64de920 | 0x63727f0..0x63729a3 | u32 at .data 0x64ffde0 | 0x14 (20) |
| opt/lg_tcache_nslots_mul | 0x64de948 | 0x63729b0..0x6372bc7 | qword at .data 0x64ffdd8 | 0x1 |

File-initial values only: `.data` is writable, so runtime values may differ.
Observed address relationship, not a proven struct claim: the five value
slots form one adjacent cluster — 0x64ffdd8 (lg_tcache_nslots_mul, u64),
0x64ffde0 (large, u32), 0x64ffde4 (small_max, u32), 0x64ffde8 (small_min,
u32), 0x64ffdf0 (tcache_max, u64) — continuing the cluster that packet
#261's tcache byte at 0x64ffdf8 closes. Whether these slots belong to one
struct is NOT proven and is left open. The three u32 FDEs are
instruction-identical modulo the value-load lea displacement and intra-FDE
jump targets (verified by a normalized instruction-level diff). After this
packet, 126 of the 204 static leaves remain unclassified.

## Claimed bytes (5 windows, 2375 bytes total)

| window | range | bytes | strict ins |
| ------ | ----- | ----- | ---------- |
| tcache_max | 0x6372250..0x6372467 | 535 | 147 |
| tcache_nslots_small_min | 0x6372470..0x6372623 | 435 | 116 |
| tcache_nslots_small_max | 0x6372630..0x63727e3 | 435 | 116 |
| tcache_nslots_large | 0x63727f0..0x63729a3 | 435 | 116 |
| lg_tcache_nslots_mul | 0x63729b0..0x6372bc7 | 535 | 147 |

Strict counts are mnemonic-line counts (address + bytes field + tab +
mnemonic starting with a lowercase letter; objdump byte-continuation lines
excluded) and match across README, records.json, and the PR body. Total:
2375 bytes, 642 strict instructions. .hex exhibits contain RAW BINARY bytes,
not hex text (format since packet #255); the verifier, tests, and MANIFEST
all treat them as raw.

Paddings to the next FDE: tcache_max → tcache_nslots_small_min 9 bytes,
tcache_nslots_small_min → tcache_nslots_small_max 13 bytes,
tcache_nslots_small_max → tcache_nslots_large 13 bytes,
tcache_nslots_large → lg_tcache_nslots_mul 13 bytes,
lg_tcache_nslots_mul → next FDE 0x6372bd0 (group 42, not claimed) 9 bytes.

## Disjointness

The verifier's collector scans the merged tree plus prior worktree records
(#183–#269), deduplicated by real packet slug, and gathers ONLY exhibited
windows: string range fields, [start, end] lists (hex strings or int pairs),
and start/end pairs inside exhibits lists or dicts, and windows lists or
dicts. It never collects enclosing-fde annotation fields (packet #259
lesson) and never collects census/cited-only metadata subtrees (packet #253
lesson). All 5 windows are disjoint from every prior claimed range, from
packet #232's merged FDE 0x63b8820..0x63b8d85 (checked explicitly), from
packet #252's r28_wait window 0x63ec890..0x63ec8a3, from packet #215's
handler FDE 0x63d9700..0x63d987b, and from each other. The slug
RE-001-node115-lu-opt-groups37-41-leaves does not collide with any
merged-tree directory. The verifier's disjointness check is what caught the
group-36 problem: its first run flagged an exact overlap between the draft
group-36 window and packet #261's exhibit, and the draft was restructured
to groups 37–41 instead of forcing the claim through. Group 36
(0x63721c0..0x6372246) is explicitly NOT claimed here.

## Verification

- Static verifier tools/node115_lu_opt_groups37_41_leaves.py (byte reads
  only; never executes the binary): exit 0.
- Own unit tests tests/test_node115_lu_opt_groups37_41_leaves.py:
  standalone, including regeneration comparison, independent strict
  recount, and tamper controls run first (hex flip, strict-count change,
  injected overlap, value-byte flip — each confirmed to fail the
  verifier, and a clean temp copy confirmed to pass).
- make verify: exit 0 (559 evidence-packet manifests, 7169 entries).
- make catalogue-check: exit 2, pre-existing Stale catalogue: README.md on
  the new base (verified: no catalogue file is touched by this packet;
  only the packet dir, tools file, and tests file are added) — not a
  packet regression, and not claimed as passing.
- Full make test is NOT attempted: 584 test files on the new base take
  hours and risk a VM-restart kill mid-run; no full-suite tally is
  claimed.
- MANIFEST.sha256 verified with sha256sum -c (all 15 entries OK).
- Self-corrections during the build: (1) a first .eh_frame census script
  parsed the FDE range field as ULEB and cut two handlers mid-instruction
  (group 36 read as 6 bytes, group 37 as 23 bytes); packet #269's verifier
  showed the range is a fixed 4-byte field, and after that fix all FDE
  bounds land on instruction boundaries with the stated paddings. (2) The
  draft packet claimed group 36 until the verifier's disjointness check
  proved packet #261 already owns that exact window; the packet was
  rebuilt as groups 37–41 with the correction recorded here. No packet
  bytes from the draft survive — the exhibits were regenerated for the
  final five leaves only.

## Not covered (explicit)

- The remaining 126 static leaves.
- The getter family and dispatcher internals beyond the leaf contract.
- Runtime values of the `.data` slots at 0x64ffdd8, 0x64ffde0, 0x64ffde4,
  0x64ffde8, and 0x64ffdf0 (only file-initial values are reported).
- Whether the five adjacent value slots belong to one struct: observed
  address proximity only, not proven.
- The largest bin_table_init caller FDE 0x63cba10 (10 sites): not decoded
  (packet #269's other option, explicitly not taken here).
- Packet #269's framings are NOT corrected or re-claimed here, except for
  its next-question pointer (group 36), which this packet corrects as
  described above; nothing in this packet's disassembly contradicts #269's
  classified leaves.

## Next question

Classify the next five leaves in tree order (opt children groups 42+,
starting with the FDE at 0x6372bd0 — opt/tcache_gc_incr_bytes, group 42,
resolved via its node 0x64de970 slot); or decode the largest bin_table_init
caller FDE 0x63cba10 (10 sites). Packet #271 should pick one of these, not
both, to stay light.
