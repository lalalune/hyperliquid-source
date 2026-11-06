# RE-001: lu opt groups 56-60 leaves

Node-115-only light packet: five more control-tree leaves classified in
tree order after packet #272's five groups 47, 51, 53, 54, 55 leaves
(opt/prof_leak, opt/prof_leak_error, opt/prof_accum,
opt/prof_recent_alloc_max, opt/prof_stats), all read-only in effect.
This packet takes packet #272's first next-question option only; the
largest bin_table_init caller FDE 0x63cba10 (10 sites) is explicitly
NOT decoded here, per #272's "pick one, not both".

## Correction to packet #272's gap note (FDE 0x6373da0 IS an opt handler)

Packet #272's body noted the 153-byte gap between group 52's end
(0x6373d97) and group 53's start (0x6373e30) and stated that the FDE
0x6373da0..0x6373e26 in that gap "is not an opt child handler — no
opt group is hidden in that gap". That statement is wrong: the FDE
is group 58's handler. Proof: group 58's node 0x64debf0, slot +0x20,
resolves via the `.rela.dyn` addend to 0x6373da0; the `.eh_frame`
FDE at 0x6373da0 runs to 0x6373e26 (134 bytes, 36 strict
instructions); its name slot +0x08 resolves to `prof_accum`; and
its body is the standard byte-leaf shape reading the byte at
`.bss` 0x6713601. The FDE was never claimed by any earlier packet
(#272 only discussed it), so it is claimed here without duplication.
This corrects #272's prose claim, not #272's classified leaves —
nothing here contradicts #272's groups 47, 51, 53, 54, 55. The
lesson restated: tree order is node order, not address order
(packet #267) — group 58's handler sits at a lower address than
groups 53–57, so an address-order gap scan cannot rule out an opt
handler hiding in it.

## Leaves (5 of the 116 remaining at packet start)

All five handlers are reached only by dispatcher indirect
tail-call: a whole-`.text` E8 census gives 0 direct entries per
leaf. Each handler's node+0x20 slot was confirmed via `.rela.dyn`
addends (60,723 `.rela.dyn` entries total, 59,534 of type
RELATIVE; file slots are zero-filled, so the addend is the
authority), and each node+0x08 name addend resolves to the leaf
name below. The five are the opt node's children-array groups
56–60 (array 0x64de2e0, 65 children, 5-qword entries, handler
slot at entry offset +32), in tree order after packet #272's
opt/prof_final. FDE bounds come from `.eh_frame`
(PC-relative sdata4 encoding, fixed 4-byte range fields — not
ULEB, per packet #270's lesson), not from endbr64 scanning.

Tree order is node order, not address order (packet #267's
lesson): here node order and address order do NOT agree — group
58's handler (0x6373da0) sits far below groups 56–57 in address
order, and group 59's handler (0x6374290) follows group 57's.
Group 56's handler (0x6374170) is exactly packet #272's
next-question FDE, verified unclaimed before building.

This batch is mixed-shape like packets #266/#267/#268/#270/#271,
not one template: four plain-byte leaves and one plain-u64 leaf.
All five share the same contract skeleton (the same shape as
packet #261's value leaves): a write attempt (newp|newlen != 0)
returns 1 without touching memory; a read with oldp==0 or
oldlenp==0 returns 0; a read with *oldlenp==size stores the
value and returns 0; any other *oldlenp takes the short-read
path (n = min(*oldlenp, size) bytes copied from a stack temp,
*oldlenp set to n, return 0x16). Single ret per FDE; all jumps
stay inside the FDE; the only out-of-FDE transfer is the
`__stack_chk_fail` call on canary mismatch.

| leaf | node | handler FDE | value | file value |
| ---- | ---- | ----------- | ----- | ---------- |
| opt/prof_leak | 0x64deba0 | 0x6374170..0x63741f6 | byte at .bss 0x6713603 | runtime (not in file) |
| opt/prof_leak_error | 0x64debc8 | 0x6374200..0x6374286 | byte at .bss 0x6713602 | runtime (not in file) |
| opt/prof_accum | 0x64debf0 | 0x6373da0..0x6373e26 | byte at .bss 0x6713601 | runtime (not in file) |
| opt/prof_recent_alloc_max | 0x64dec18 | 0x6374290..0x63744a7 | qword at .bss 0x6715910 | runtime (not in file) |
| opt/prof_stats | 0x64dec40 | 0x63744b0..0x6374536 | byte at .bss 0x6717690 | runtime (not in file) |

File-initial values only: `.bss` values are not in the file at
all. Observed address relationship, not a proven struct claim:
the byte slots 0x6713601 (accum), 0x6713602 (leak_error),
0x6713603 (leak), 0x6713604 (prof_final, packet #272), and
0x6713605 (prof_gdump, packet #272) are five adjacent bytes.
Whether they belong to one struct is NOT proven and is left
open. The four byte FDEs are instruction-identical modulo the
value-load lea displacement and intra-FDE jump targets
(verified by a normalized instruction-level diff). After this
packet, 111 of the 204 static leaves remain unclassified.

## Exhibits (5 windows, 1071 bytes, 291 strict lines)

Strict = address + bytes field + tab + mnemonic starting with a
lowercase letter; objdump byte-continuation lines excluded.
`.hex` exhibits contain raw binary bytes, not hex text.

| exhibit | range | bytes | strict |
| ------- | ----- | ----- | ------ |
| prof_leak | 0x6374170..0x63741f6 | 134 | 36 |
| prof_leak_error | 0x6374200..0x6374286 | 134 | 36 |
| prof_accum | 0x6373da0..0x6373e26 | 134 | 36 |
| prof_recent_alloc_max | 0x6374290..0x63744a7 | 535 | 147 |
| prof_stats | 0x63744b0..0x6374536 | 134 | 36 |

Paddings to the next FDE: prof_leak → prof_leak_error 10 bytes,
prof_leak_error → prof_recent_alloc_max 10 bytes, prof_accum →
group 53's handler (0x6373e30, claimed by #272) 10 bytes,
prof_recent_alloc_max → prof_stats 9 bytes, prof_stats → next
FDE 0x6374540 (group 61, not claimed) 10 bytes.

## Verification

- Static verifier `tools/node115_lu_opt_groups56_60_leaves.py`
  (byte reads only; never executes the binary): exit 0.
- Own unit tests `tests/test_node115_lu_opt_groups56_60_leaves.py`:
  standalone, including regeneration comparison, independent
  strict recount, and tamper controls run first (hex flip,
  strict-count change, injected overlap, value-slot change —
  each confirmed to fail the verifier, and a clean temp copy
  confirmed to pass).
- `make verify`: exit 0 (559 evidence-packet manifests, 7169
  entries — actual tally: base 7154 + this packet's 15 MANIFEST
  entries).
- `make catalogue-check`: exit 2, pre-existing `Stale catalogue:
  README.md` on the new base (verified: no catalogue file is
  touched by this packet; only the packet dir, tools file, and
  tests file are added) — not a packet regression, and not
  claimed as passing.
- Full `make test` is NOT attempted: 584 test files on the new
  base take hours and risk a VM-restart kill mid-run; no
  full-suite tally is claimed.
- MANIFEST.sha256 verified with `sha256sum -c` (all 15 entries
  OK).

## Disjointness

The verifier's collector scans the merged tree plus prior
worktree records (#183–#272), deduplicated by real packet slug,
and gathers ONLY exhibited windows: string range fields,
[start, end] lists (hex strings or int pairs), and start/end
pairs inside exhibits lists or dicts, and windows lists or
dicts. It never collects enclosing-fde annotation fields
(packet #259 lesson) and never collects census/cited-only
metadata subtrees (packet #253 lesson). All 5 windows are
disjoint from every prior claimed range, from packet #232's
merged FDE `0x63b8820..0x63b8d85` (checked explicitly), from
packet #252's r28_wait window `0x63ec890..0x63ec8a3`, from
packet #215's handler FDE `0x63d9700..0x63d987b`, from packet
#261's group-36 tcache window `0x63721c0..0x6372246`, from
packet #261's opt_prof window `0x63737c0..0x6373846`, and from
packet #262's prof_prefix, prof_active, and lg_prof_sample
windows, and from each other. The slug
`RE-001-node115-lu-opt-groups56-60-leaves` does not collide
with any merged-tree directory. Group 56's handler (0x6374170)
is exactly packet #272's next-question FDE, verified unclaimed
before building (packet #270's lesson: a pointer is not a
claim of availability).

## Not covered (explicit)

- The remaining 111 static leaves.
- The getter family and dispatcher internals beyond the leaf
  contract.
- Runtime values of the `.bss` bytes at 0x6713601, 0x6713602,
  0x6713603, 0x6717690, and the `.bss` qword at 0x6715910
  (only the mechanism is reported; values are runtime).
- Whether the adjacent `.bss` bytes belong to one struct:
  observed address proximity only, not proven.
- The largest bin_table_init caller FDE 0x63cba10 (10 sites):
  not decoded (packet #272's other option, explicitly not taken
  here).
- Packet #272's framings are NOT corrected or re-claimed here,
  except for its gap-FDE note (0x6373da0), which this packet
  corrects as described above; nothing in this packet's
  disassembly contradicts #272's classified leaves.

## Next question

Classify the next five leaves in tree order (opt children groups
61+, starting with the FDE at 0x6374540 — opt/prof_sys_thread_name,
group 61, resolved via its node 0x64dec68 slot); or decode the
largest bin_table_init caller FDE 0x63cba10 (10 sites). Packet
#274 should pick one of these, not both, to stay light — and,
per the #270/#272 lessons, must verify every group in its window
against prior exhibits before building, not just the first FDE.
