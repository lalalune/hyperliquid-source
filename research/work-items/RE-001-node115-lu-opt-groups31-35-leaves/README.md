# RE-001-node115-lu-opt-groups31-35-leaves

Node-115-only light packet: five more control-tree leaves classified in tree
order after packet #268's five groups 26–30 leaves. This packet takes packet
#268's first next-question option only; the largest bin_table_init caller FDE
0x63cba10 (10 sites) is explicitly NOT decoded here, per #268's "pick one,
not both".

## Classified leaves (5 of the 136 remaining at packet start)

All five handlers are reached only by dispatcher indirect tail-call: a
whole-`.text` E8 census gives 0 direct entries per leaf. Each handler's
node+0x20 slot was confirmed via `.rela.dyn` addends (60,723 `.rela.dyn`
entries total, 59,534 of type RELATIVE; file slots are zero-filled, so the
addend is the authority), and each node+0x08 name addend resolves to the leaf
name below. The five are the opt node's children-array groups 31–35 (array
0x64de2e0, 65 children, 5-qword entries, handler slot at entry offset +32),
in tree order after packet #268's opt/stats_interval_opts. FDE bounds come
from `.eh_frame` (PC-relative sdata4 encoding), not from endbr64 scanning.

Tree order is node order, not address order (packet #267's lesson): here
groups 31–32 are contiguous in the chain region, while groups 33–35 have
scattered stub handlers — node order still defines the sequence, and no
group is skipped. Group 31's handler (0x6371f10) is exactly packet #268's
next-question FDE.

This batch is mixed-shape like packets #266/#267/#268, not one template:
two value leaves and three constant-return stubs — a shape not seen in the
preceding leaf packets. The two value leaves share the contract skeleton of
packet #261's value leaves: a write attempt (newp|newlen != 0) returns 1
without touching memory; a read with oldp==0 or oldlenp==0 returns 0; a read
with *oldlenp==size stores the value and returns 0; any other *oldlenp takes
the short-read path (n = min(*oldlenp, size) bytes copied from a stack temp,
*oldlenp set to n, return 0x16). Single ret per FDE; all jumps stay inside
the FDE; the only out-of-FDE transfer is the `__stack_chk_fail` call on
canary mismatch.

The three stub leaves are a different, simpler shape: each handler is exactly
10 bytes — endbr64, `mov $0x2,%eax`, ret. No stack frame, no canary, no
calls, no jumps, no memory access of any kind. Every call into one of these
leaves returns 2 unconditionally, whatever arguments are passed. This packet
claims only that observed behaviour; it does not interpret the 2 (the
dispatcher-side meaning of the return value is not decoded here).

| leaf | node | handler FDE | value | file value |
| ---- | ---- | ----------- | ----- | ---------- |
| opt/junk | 0x64de7b8 | 0x6371f10..0x6372127 | u64 at .data 0x64ffb60 | 0x0 |
| opt/zero | 0x64de7e0 | 0x6372130..0x63721b6 | byte at .bss 0x6511738 | runtime (not in file) |
| opt/utrace | 0x64de808 | 0x636c7b0..0x636c7ba | constant return 2 | — (no value slot) |
| opt/xmalloc | 0x64de830 | 0x6378090..0x637809a | constant return 2 | — (no value slot) |
| opt/experimental_infallible_new | 0x64de858 | 0x6377db0..0x6377dba | constant return 2 | — (no value slot) |

File-initial values only: `.data` is writable, so runtime values may differ;
`.bss` values are not in the file at all. The three stub exhibits are
byte-identical (all three handlers are the same 10 bytes); their objdump
exhibits differ only in the address column. An opt-children-array census
confirms each stub address is the handler slot of exactly one opt group
(33, 34, 35 respectively) — the stubs are not shared between groups.
After this packet, 131 of the 204 static leaves remain unclassified.

## Claimed bytes (5 windows, 699 bytes total)

| window | range | bytes | strict ins |
| ------ | ----- | ----- | ---------- |
| junk | 0x6371f10..0x6372127 | 535 | 147 |
| zero | 0x6372130..0x63721b6 | 134 | 36 |
| utrace | 0x636c7b0..0x636c7ba | 10 | 3 |
| xmalloc | 0x6378090..0x637809a | 10 | 3 |
| experimental_infallible_new | 0x6377db0..0x6377dba | 10 | 3 |

Strict counts are mnemonic-line counts (address + bytes field + tab +
mnemonic starting with a lowercase letter; objdump byte-continuation lines
excluded) and match across README, records.json, and the PR body. Total:
699 bytes, 192 strict instructions. .hex exhibits contain RAW BINARY bytes,
not hex text (format since packet #255); the verifier, tests, and MANIFEST
all treat them as raw.

Paddings to the next FDE: junk → zero 9 bytes, zero → next FDE 0x63721c0
(group 36, not claimed) 10 bytes, utrace → next FDE 0x636c7c0 6 bytes,
xmalloc → next FDE 0x63780a0 6 bytes, experimental_infallible_new → next
FDE 0x6377dc0 6 bytes. The 6-byte stub paddings are int3 bytes.

## Disjointness

The verifier's collector scans the merged tree plus prior worktree records
(#183–#268), deduplicated by real packet slug, and gathers ONLY exhibited
windows: string range fields, [start, end] lists (hex strings or int pairs),
and start/end pairs inside exhibits lists or dicts, and windows lists or
dicts. It never collects enclosing-fde annotation fields (packet #259
lesson) and never collects census/cited-only metadata subtrees (packet #253
lesson). All 5 windows are disjoint from every prior claimed range, from
packet #232's merged FDE 0x63b8820..0x63b8d85 (checked explicitly), from
packet #252's r28_wait window 0x63ec890..0x63ec8a3, from packet #215's
handler FDE 0x63d9700..0x63d987b, and from each other. The slug
RE-001-node115-lu-opt-groups31-35-leaves does not collide with any
merged-tree directory. Note: the only prior mention of 0x6371f10 is packet
#268's `next_fde_after_last` pointer — cited-only metadata, not a claim,
and it is exactly this packet's group-31 handler, as #268's next question
invited.

## Verification

- Static verifier tools/node115_lu_opt_groups31_35_leaves.py (byte reads
  only; never executes the binary): exit 0.
- Own unit tests tests/test_node115_lu_opt_groups31_35_leaves.py:
  standalone, including regeneration comparison, independent strict
  recount, and tamper controls run first (hex flip, strict-count change,
  injected overlap, stub-immediate flip — each confirmed to fail the
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
- Self-corrections during the build: none affecting packet bytes. The
  first census script had a name-decode bug (names printed as None); the
  handler addresses were unaffected, and names were re-resolved from the
  .rela.dyn addends and cross-checked against the node slots before any
  packet text was written.

## Not covered (explicit)

- The remaining 131 static leaves.
- The getter family and dispatcher internals beyond the leaf contract.
- Runtime values of the `.bss` byte at 0x6511738 and runtime values of the
  `.data` qword at 0x64ffb60 (only file-initial values are reported).
- What the dispatcher does with a stub's return value 2: the stubs'
  behaviour (return 2, touch nothing) is observed; its caller-side meaning
  is not decoded here.
- The largest bin_table_init caller FDE 0x63cba10 (10 sites): not decoded
  (packet #268's other option, explicitly not taken here).
- Packet #268's framings are NOT corrected or re-claimed here; nothing in
  this packet's disassembly contradicts them.

## Next question

Classify the next five leaves in tree order (opt children groups 36+,
starting with the FDE at 0x63721c0 — opt/tcache, group 36, resolved via
its node 0x64de880 slot); or decode the largest bin_table_init caller FDE
0x63cba10 (10 sites). Packet #270 should pick one of these, not both, to
stay light.
