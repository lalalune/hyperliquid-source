# RE-001-node115-lu-opt-groups42-46-leaves

Node-115-only light packet: five more control-tree leaves classified in
tree order after packet #270's five groups 37–41 leaves
(opt/tcache_gc_incr_bytes, opt/tcache_gc_delay_bytes,
opt/lg_tcache_flush_small_div, opt/lg_tcache_flush_large_div, opt/thp),
all read-only in effect. This packet takes packet #270's first
next-question option only; the largest bin_table_init caller FDE
0x63cba10 (10 sites) is explicitly NOT decoded here, per #270's "pick
one, not both".

## Leaves (5 of the 126 remaining at packet start)

All five handlers are reached only by dispatcher indirect tail-call: a
whole-`.text` E8 census gives 0 direct entries per leaf. Each handler's
node+0x20 slot was confirmed via `.rela.dyn` addends (60,723 `.rela.dyn`
entries total, 59,534 of type RELATIVE; file slots are zero-filled, so
the addend is the authority), and each node+0x08 name addend resolves
to the leaf name below. The five are the opt node's children-array
groups 42–46 (array 0x64de2e0, 65 children, 5-qword entries, handler
slot at entry offset +32), in tree order after packet #270's
opt/lg_tcache_nslots_mul. FDE bounds come from `.eh_frame`
(PC-relative sdata4 encoding, fixed 4-byte range fields — not ULEB, per
packet #270's lesson), not from endbr64 scanning.

Tree order is node order, not address order (packet #267's lesson):
here node order and address order happen to agree — group 42's handler
(0x6372bd0) is also the lowest address among the five, matching packet
#270's next question ("starting with the FDE at 0x6372bd0").

This batch is mixed-shape like packets #266/#267/#268/#270, not one
template: two plain-u64 leaves, two plain-u32 leaves, and one
indirect-table leaf. The four value leaves share the same contract
skeleton (the same shape as packet #261's value leaves): a write
attempt (newp|newlen != 0) returns 1 without touching memory; a read
with oldp==0 or oldlenp==0 returns 0; a read with *oldlenp==size
stores the value and returns 0; any other *oldlenp takes the
short-read path (n = min(*oldlenp, size) bytes copied from a stack
temp, *oldlenp set to n, return 0x16). Single ret per FDE; all jumps
stay inside the FDE; the only out-of-FDE transfer is the
`__stack_chk_fail` call on canary mismatch.

The thp leaf is a different shape: it reads a u32 index from .bss
0x6712378, then returns the qword at .data table base 0x64ffcc0
indexed by that value (mov (%rsi,%rcx,8),%rdi). The returned value is
therefore runtime-determined by the index; the table itself is
file-populated (file-initial entries at indices 4–8 are 0x1,
0xffffffffffffffff, 0x13, 0x101, 0xffffffffffffffff). This packet
claims only the observed mechanism, not any particular returned value.

| leaf | node | handler FDE | value | file value |
| ---- | ---- | ----------- | ----- | ---------- |
| opt/tcache_gc_incr_bytes | 0x64de970 | 0x6372bd0..0x6372de7 | qword at .data 0x64ffdd0 | 0x10000 (65536) |
| opt/tcache_gc_delay_bytes | 0x64de998 | 0x6372df0..0x6373007 | qword at .bss 0x6728870 | runtime (not in file) |
| opt/lg_tcache_flush_small_div | 0x64de9c0 | 0x6373010..0x63731c3 | u32 at .data 0x64ffdcc | 0x1 |
| opt/lg_tcache_flush_large_div | 0x64de9e8 | 0x63731d0..0x6373383 | u32 at .data 0x64ffdc8 | 0x1 |
| opt/thp | 0x64dea10 | 0x6373390..0x637359d | qword table at .data 0x64ffcc0 indexed by u32 at .bss 0x6712378 | runtime (index in .bss) |

File-initial values only: `.data` is writable, so runtime values may
differ; `.bss` values are not in the file at all. Observed address
relationship, not a proven struct claim: the gc/flush value slots
(0x64ffdc8, 0x64ffdcc, 0x64ffdd0) continue downward the cluster that
packet #270's slots (0x64ffdd8–0x64ffdf8) form; the thp table base
0x64ffcc0 sits 0x108 below that cluster. Whether these slots belong
to one struct is NOT proven and is left open. The two u64 FDEs are
instruction-identical modulo the value-load lea displacement and
intra-FDE jump targets, as are the two u32 FDEs (verified by a
normalized instruction-level diff). After this packet, 121 of the 204
static leaves remain unclassified.

## Exhibits (5 windows, 2465 bytes, 675 strict lines)

Strict = address + bytes field + tab + mnemonic starting with a
lowercase letter; objdump byte-continuation lines excluded.
`.hex` exhibits contain raw binary bytes, not hex text.

| exhibit | range | bytes | strict |
| ------- | ----- | ----- | ------ |
| tcache_gc_incr_bytes | 0x6372bd0..0x6372de7 | 535 | 147 |
| tcache_gc_delay_bytes | 0x6372df0..0x6373007 | 535 | 147 |
| lg_tcache_flush_small_div | 0x6373010..0x63731c3 | 435 | 116 |
| lg_tcache_flush_large_div | 0x63731d0..0x6373383 | 435 | 116 |
| thp | 0x6373390..0x637359d | 525 | 149 |

Paddings to the next FDE: tcache_gc_incr_bytes →
tcache_gc_delay_bytes 9 bytes, tcache_gc_delay_bytes →
lg_tcache_flush_small_div 9 bytes, lg_tcache_flush_small_div →
lg_tcache_flush_large_div 13 bytes, lg_tcache_flush_large_div → thp
13 bytes, thp → next FDE 0x63735a0 (group 47, not claimed) 3 bytes.

## Verification

- Static verifier tools/node115_lu_opt_groups42_46_leaves.py (byte
  reads only; never executes the binary): exit 0.
- Own unit tests tests/test_node115_lu_opt_groups42_46_leaves.py:
  standalone, 24/24 pass, including regeneration comparison,
  independent strict recount, and tamper controls run first (hex flip,
  strict-count change, injected overlap, value-byte flip, thp
  table-base flip — each confirmed to fail the verifier, and a clean
  temp copy confirmed to pass).
- make verify: exit 0 (559 evidence-packet manifests, 7169 entries —
  actual tally: base 7154 + this packet's 15 MANIFEST entries).
- make catalogue-check: exit 2, pre-existing Stale catalogue:
  README.md on the new base (verified: no catalogue file is touched
  by this packet; only the packet dir, tools file, and tests file are
  added) — not a packet regression, and not claimed as passing.
- Full make test is NOT attempted: 584 test files on the new base
  take hours and risk a VM-restart kill mid-run; no full-suite tally
  is claimed.
- MANIFEST.sha256 verified with sha256sum -c (all 15 entries OK).

## Disjointness

The verifier's collector scans the merged tree plus prior worktree
records (#183–#270), deduplicated by real packet slug, and gathers
ONLY exhibited windows: string range fields, [start, end] lists (hex
strings or int pairs), and start/end pairs inside exhibits lists or
dicts, and windows lists or dicts. It never collects enclosing-fde
annotation fields (packet #259 lesson) and never collects
census/cited-only metadata subtrees (packet #253 lesson). All 5
windows are disjoint from every prior claimed range, from packet
#232's merged FDE 0x63b8820..0x63b8d85 (checked explicitly), from
packet #252's r28_wait window 0x63ec890..0x63ec8a3, from packet
#215's handler FDE 0x63d9700..0x63d987b, from packet #261's
group-36 tcache window 0x63721c0..0x6372246, and from each other.
The slug RE-001-node115-lu-opt-groups42-46-leaves does not collide
with any merged-tree directory. Group 42's handler (0x6372bd0) is
exactly packet #270's next-question FDE, verified unclaimed before
building (packet #270's lesson: a pointer is not a claim of
availability).

## Not covered (explicit)

- The remaining 121 static leaves.
- The getter family and dispatcher internals beyond the leaf
  contract.
- Runtime values of the `.bss` qword at 0x6728870, the `.bss` index
  at 0x6712378, and runtime values of the `.data` slots at 0x64ffdc8,
  0x64ffdcc, 0x64ffdd0 (only file-initial values are reported).
- Which table entry thp returns for any particular runtime index:
  the mechanism is observed; the returned value is runtime-determined.
- Whether the value slots belong to one struct: observed address
  proximity only, not proven.
- The largest bin_table_init caller FDE 0x63cba10 (10 sites):
  not decoded (packet #270's other option, explicitly not taken
  here).
- Packet #270's framings are NOT corrected or re-claimed here;
  nothing in this packet's disassembly contradicts them.

## Next question

Classify the next five leaves in tree order (opt children groups 47+,
starting with the FDE at 0x63735a0); or decode the largest
bin_table_init caller FDE 0x63cba10 (10 sites). Packet #272 should
pick one of these, not both, to stay light.
