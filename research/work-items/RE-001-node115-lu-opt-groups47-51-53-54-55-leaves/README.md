# RE-001-node115-lu-opt-groups47-51-53-54-55-leaves

Node-115-only light packet: five more control-tree leaves classified in
tree order after packet #271's five groups 42–46 leaves. The five are
opt children groups 47, 51, 53, 54, 55 — NOT a contiguous range: groups
48, 49, 50, and 52 were already claimed by earlier packets and are skipped
without re-claim (see "Correction to packet #271's next question" below).
All five leaves are read-only in effect and share the packet #261 contract
skeleton: a write attempt (newp|newlen != 0) returns 1 without touching
memory; a read with oldp==0 or oldlenp==0 returns 0; a read with
*oldlenp==size stores the value and returns 0; any other *oldlenp takes
the short-read path (n = min(*oldlenp, size) bytes copied from a stack
temp, *oldlenp set to n, return 0x16). Single ret per FDE; all jumps stay
inside the FDE; the only out-of-FDE transfer is the `__stack_chk_fail`
call on canary mismatch.

## Correction to packet #271's next question (groups 48–50, 52 already claimed)

Packet #271's next question named groups 47+ as the next five groups to
classify. That pointer is partly wrong: four of the five groups in the
47–51 window, plus group 52, were already classified:

- Group 48 (opt/prof, FDE 0x63737c0..0x6373846, 134B/36 strict) — packet
  #261 (PR #2804), exhibit opt_prof.
- Group 49 (opt/prof_prefix, FDE 0x6373850..0x6373a5a, 522B/146 strict) —
  packet #262 (PR #2810), exhibit prof_prefix.
- Group 50 (opt/prof_active, FDE 0x6373a60..0x6373ae6, 134B/36 strict) —
  packet #262 (PR #2810), exhibit prof_active.
- Group 52 (opt/lg_prof_sample, FDE 0x6373b80..0x6373d97, 535B/147
  strict) — packet #262 (PR #2810), exhibit lg_prof_sample.

Each match was verified by exact FDE-range equality against the prior
packets' records.json files, not by name alone. Re-claiming any of them
would duplicate a submitted packet (the packet #250 lesson: an assigned
neighbour topic that turns out to be already claimed must be dropped, not
built on). The four groups are therefore skipped without re-claim, and
this packet classifies the next five unclaimed groups in tree order
instead: 47, 51, 53, 54, 55. No group is skipped silently — the skips and
their proof are stated here and recorded under the records "cited"
subtree, which the verifier's range collector excludes (packet #253
lesson: census/cited-only metadata is not a claim).

Group 47's handler (0x63735a0) is exactly packet #271's next-question
FDE, verified unclaimed before building (packet #270's lesson: a pointer
is not a claim of availability).

## Classified leaves (5 of the 121 remaining at packet start)

All five handlers are reached only by dispatcher indirect tail-call: a
whole-`.text` E8 census gives 0 direct entries per leaf. Each handler's
node+0x20 slot was confirmed via `.rela.dyn` addends (60,723 `.rela.dyn`
entries total, 59,534 of type RELATIVE; file slots are zero-filled, so
the addend is the authority), and each node+0x08 name addend resolves to
the leaf name below. The five are the opt node's children-array groups
47, 51, 53, 54, 55 (array 0x64de2e0, 65 children, 5-qword entries,
handler slot at entry offset +32), in tree order after packet #271's
opt/thp. FDE bounds come from `.eh_frame` (PC-relative sdata4 encoding,
fixed 4-byte range fields — not ULEB, per packet #270's lesson), not from
endbr64 scanning.

Tree order is node order, not address order (packet #267's lesson): here
node order and address order happen to agree — group 47's handler
(0x63735a0) is also the lowest address among the five.

This batch is mixed-shape like packets #266/#267/#268/#270/#271, not one
template: two plain-u64 leaves and three plain-byte leaves. The two u64
FDEs are instruction-identical modulo the value-load lea displacement
and intra-FDE jump targets (verified by a normalized instruction-level
diff), as are the three byte FDEs.

| leaf | node | handler FDE | value | file value |
| ---- | ---- | ----------- | ----- | ---------- |
| opt/lg_extent_max_active_fit | 0x64dea38 | 0x63735a0..0x63737b7 | u64 at .data 0x64ffbe8 | 0x6 |
| opt/prof_thread_active_init | 0x64dead8 | 0x6373af0..0x6373b76 | byte at .data 0x64ffcf8 | 0x1 |
| opt/lg_prof_interval | 0x64deb28 | 0x6373e30..0x6374047 | u64 at .data 0x64ffce8 | 0xffffffffffffffff |
| opt/prof_gdump | 0x64deb50 | 0x6374050..0x63740d6 | byte at .bss 0x6713605 | runtime (not in file) |
| opt/prof_final | 0x64deb78 | 0x63740e0..0x6374166 | byte at .bss 0x6713604 | runtime (not in file) |

File-initial values only: `.data` is writable, so runtime values may
differ; `.bss` values are not in the file at all. Observed address
relationship, not a proven struct claim: prof_gdump reads the byte at
0x6713605 and prof_final reads the byte at 0x6713604 — adjacent bytes,
and prof_thread_active_init's byte at .data 0x64ffcf8 sits adjacent to
packet #262's prof_active byte at .data 0x64ffcf9. Whether any of these
bytes belong to one struct is NOT proven and is left open. After this
packet, 116 of the 204 static leaves remain unclassified.

## Claimed bytes (5 windows, 1472 bytes total)

| window | range | bytes | strict ins |
| ------ | ----- | ----- | ---------- |
| lg_extent_max_active_fit | 0x63735a0..0x63737b7 | 535 | 147 |
| prof_thread_active_init | 0x6373af0..0x6373b76 | 134 | 36 |
| lg_prof_interval | 0x6373e30..0x6374047 | 535 | 147 |
| prof_gdump | 0x6374050..0x63740d6 | 134 | 36 |
| prof_final | 0x63740e0..0x6374166 | 134 | 36 |

Strict counts are mnemonic-line counts (address + bytes field + tab +
mnemonic starting with a lowercase letter; objdump byte-continuation
lines excluded) and match across README, records.json, and the PR body.
Total: 1472 bytes, 402 strict instructions. .hex exhibits contain RAW
BINARY bytes, not hex text (format since packet #255); the verifier,
tests, and MANIFEST all treat them as raw.

Paddings to the next FDE: lg_extent_max_active_fit → group 48's handler
(0x63737c0, claimed by #261, not claimed here) 9 bytes;
prof_thread_active_init → group 52's handler (0x6373b80, claimed by
#262, not claimed here) 10 bytes; lg_prof_interval → prof_gdump 9
bytes; prof_gdump → prof_final 10 bytes; prof_final → next FDE
0x6374170 (group 56, opt/prof_leak, not claimed) 10 bytes. Note the
153-byte gap between group 52's end (0x6373d97) and group 53's start
(0x6373e30): it holds the FDE 0x6373da0..0x6373e26, which is not an opt
child handler — no opt group is hidden in that gap.

## Disjointness

The verifier's collector scans the merged tree plus prior worktree
records (#183–#271), deduplicated by real packet slug, and gathers ONLY
exhibited windows: string range fields, [start, end] lists (hex strings
or int pairs), and start/end pairs inside exhibits lists or dicts, and
windows lists or dicts. It never collects enclosing-fde annotation
fields (packet #259 lesson) and never collects census/cited-only
metadata subtrees (packet #253 lesson) — so the four skipped groups'
ranges, recorded under "cited", are not counted as this packet's claims.
All 5 windows are disjoint from every prior claimed range, from packet
#232's merged FDE 0x63b8820..0x63b8d85 (checked explicitly), from packet
#252's r28_wait window 0x63ec890..0x63ec8a3, from packet #215's handler
FDE 0x63d9700..0x63d987b, from packet #261's group-36 tcache window
0x63721c0..0x6372246, from packet #261's opt_prof window
0x63737c0..0x6373846, and from packet #262's prof_prefix, prof_active,
and lg_prof_sample windows, and from each other. The slug
RE-001-node115-lu-opt-groups47-51-53-54-55-leaves does not collide with
any merged-tree directory.

## Verification

- Static verifier tools/node115_lu_opt_groups47_51_53_54_55_leaves.py
  (byte reads only; never executes the binary): exit 0.
- Own unit tests tests/test_node115_lu_opt_groups47_51_53_54_55_leaves.py:
  standalone, all pass, including regeneration comparison, independent
  strict recount, and tamper controls run first (hex flip, strict-count
  change, injected overlap, value-byte flip, byte-slot flip — each
  confirmed to fail the verifier, and a clean temp copy confirmed to
  pass).
- make verify: exit 0 (559 evidence-packet manifests, 7169 entries —
  actual tally: base 7154 + this packet's 15 MANIFEST entries).
- make catalogue-check: exit 2, pre-existing Stale catalogue: README.md
  on the new base (verified: no catalogue file is touched by this
  packet; only the packet dir, tools file, and tests file are added) —
  not a packet regression, and not claimed as passing.
- Full make test is NOT attempted: 584 test files on the new base take
  hours and risk a VM-restart kill mid-run; no full-suite tally is
  claimed.
- MANIFEST.sha256 verified with sha256sum -c (all 15 entries OK).

## Not covered (explicit)

- The remaining 116 static leaves.
- The getter family and dispatcher internals beyond the leaf contract.
- Runtime values of the `.bss` bytes at 0x6713604 and 0x6713605 and
  runtime values of the `.data` slots at 0x64ffbe8, 0x64ffce8, and
  0x64ffcf8 (only file-initial values are reported).
- Whether the adjacent bytes/slots belong to one struct: observed
  address proximity only, not proven.
- The largest bin_table_init caller FDE 0x63cba10 (10 sites): not
  decoded (packet #271's other option, explicitly not taken here).
- Packet #271's framings are NOT corrected or re-claimed here, except
  for its next-question pointer (groups 48–50, 52), which this packet
  corrects as described above; nothing in this packet's disassembly
  contradicts #271's classified leaves.

## Next question

Classify the next five leaves in tree order (opt children groups 56+,
starting with the FDE at 0x6374170 — opt/prof_leak, group 56, resolved
via its node 0x64deba0 slot); or decode the largest bin_table_init
caller FDE 0x63cba10 (10 sites). Packet #273 should pick one of these,
not both, to stay light.
