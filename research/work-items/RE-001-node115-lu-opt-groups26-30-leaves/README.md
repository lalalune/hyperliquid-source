# RE-001-node115-lu-opt-groups26-30-leaves

Node-115-only light packet: five more control-tree leaves classified
in tree order after packet #267's five groups 21–25 leaves
(opt/muzzy_decay_ms, opt/stats_print, opt/stats_print_opts,
opt/stats_interval, opt/stats_interval_opts), all read-only.
This packet takes packet #267's first next-question option only;
the largest bin_table_init caller FDE `0x63cba10` (10 sites) is
explicitly NOT decoded here, per #267's "pick one, not both".

## Leaves (5 of the 141 remaining at packet start)

All five handlers are reached only by dispatcher indirect
tail-call: a whole-`.text` E8 census gives 0 direct entries per
leaf. Each handler's node+0x20 slot was confirmed via `.rela.dyn`
addends (60,723 `.rela.dyn` entries total, 59,534 of type
RELATIVE; file slots are zero-filled, so the addend is the
authority), and each node+0x08 name addend resolves to the leaf
name below. The five are the opt node's children-array groups
26–30 (array `0x64de2e0`, 65 children, 5-qword entries, handler
slot at entry offset +32), in tree order after packet #267's
opt/dirty_decay_ms. FDE bounds come from `.eh_frame`
(PC-relative sdata4 encoding), not from endbr64 scanning.

Tree order is node order, not address order (packet #267's
lesson): here node order and address order happen to agree —
group 26's handler (`0x6371620`) is also the lowest address
among the five, matching packet #267's next question
("starting with the FDE at `0x6371620`").

This batch is mixed-shape like packets #266/#267, not one
template: one plain-u64 leaf, one byte leaf, two pointer leaves
(value = the address itself), and one plain-u64 leaf. All five
share the same contract skeleton (the same shape as packet
#261's value leaves): a write attempt (newp|newlen != 0)
returns 1 without touching memory; a read with oldp==0 or
oldlenp==0 returns 0; a read with *oldlenp==size stores the
value and returns 0; any other *oldlenp takes the short-read
path (n = min(*oldlenp, size) bytes copied from a stack temp,
*oldlenp set to n, return 0x16). Single ret per FDE; all jumps
stay inside the FDE; the only out-of-FDE transfer is the
`__stack_chk_fail` call on canary mismatch.

| leaf | node | handler FDE | value | file value |
| ---- | ---- | ----------- | ----- | ---------- |
| opt/muzzy_decay_ms | 0x64de6f0 | 0x6371620..0x6371837 | u64 at .bss 0x6711a88 | runtime (not in file) |
| opt/stats_print | 0x64de718 | 0x6371840..0x63718c6 | byte at .bss 0x672778b | runtime (not in file) |
| opt/stats_print_opts | 0x64de740 | 0x63718d0..0x6371ada | address .bss 0x6727780 itself | address itself |
| opt/stats_interval | 0x64de768 | 0x6371ae0..0x6371cf7 | u64 at .data 0x64ffd00 | 0xffffffffffffffff |
| opt/stats_interval_opts | 0x64de790 | 0x6371d00..0x6371f0a | address .bss 0x6727770 itself | address itself |

File-initial values only: `.data` is writable, so runtime values
may differ; `.bss` values are not in the file at all. Observed
address relationship, not a proven struct claim: stats_print
reads the byte at `0x672778b`, which is 0xb past the `0x6727780`
base that stats_print_opts returns; stats_interval_opts returns
the neighbouring base `0x6727770` (0x10 below). Whether these
three addresses belong to one struct is NOT proven and is left
open. After this packet, 136 of the 204 static leaves remain
unclassified.

## Exhibits (5 windows, 2248 bytes, 622 strict lines)

Strict = address + bytes field + tab + mnemonic starting with a
lowercase letter; objdump byte-continuation lines excluded.

| exhibit | range | bytes | strict |
| ------- | ----- | ----- | ------ |
| muzzy_decay_ms | `0x6371620..0x6371837` | 535 | 147 |
| stats_print | `0x6371840..0x63718c6` | 134 | 36 |
| stats_print_opts | `0x63718d0..0x6371ada` | 522 | 146 |
| stats_interval | `0x6371ae0..0x6371cf7` | 535 | 147 |
| stats_interval_opts | `0x6371d00..0x6371f0a` | 522 | 146 |

Paddings to the next FDE: muzzy_decay_ms → stats_print 9 bytes,
stats_print → stats_print_opts 10 bytes, stats_print_opts →
stats_interval 6 bytes, stats_interval → stats_interval_opts
9 bytes, stats_interval_opts → next FDE `0x6371f10` (group 31,
not claimed) 6 bytes.

## Verification

- Static verifier `tools/node115_lu_opt_groups26_30_leaves.py`
  (byte reads only; never executes the binary): exit 0.
- Own unit tests `tests/test_node115_lu_opt_groups26_30_leaves.py`:
  standalone, including regeneration comparison, independent
  strict recount, and tamper controls run first (hex flip,
  strict-count change, injected overlap — each confirmed to fail
  the verifier, and a clean temp copy confirmed to pass).
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
worktree records (#183–#267), deduplicated by real packet slug,
and gathers ONLY exhibited windows: string range fields,
[start, end] lists (hex strings or int pairs), and start/end
pairs inside exhibits lists or dicts, and windows lists or
dicts. It never collects enclosing-fde annotation fields
(packet #259 lesson) and never collects census/cited-only
metadata subtrees (packet #253 lesson). All 5 windows are
disjoint from every prior claimed range, from packet #232's
merged FDE `0x63b8820..0x63b8d85` (checked explicitly), from
packet #252's r28_wait window `0x63ec890..0x63ec8a3`, from
packet #215's handler FDE `0x63d9700..0x63d987b`, and from each
other. The slug `RE-001-node115-lu-opt-groups26-30-leaves` does
not collide with any merged-tree directory.

## Not covered (explicit)

- The remaining 136 static leaves.
- The getter family and dispatcher internals beyond the leaf
  contract.
- Runtime values of the `.bss` globals `0x6711a88`,
  `0x672778b`, and the `.bss` buffers at `0x6727780` /
  `0x6727770`, and runtime values of the `.data` qword at
  `0x64ffd00` (only file-initial values are reported).
- Whether `0x6727770`, `0x6727780`, and `0x672778b` belong to
  one struct: observed address proximity only, not proven.
- The largest bin_table_init caller FDE `0x63cba10` (10 sites):
  not decoded (packet #267's other option, explicitly not taken
  here).
- Packet #267's framings are NOT corrected or re-claimed here;
  nothing in this packet's disassembly contradicts them.

## Next question

Classify the next five leaves in tree order (opt children groups
31+, starting with the FDE at `0x6371f10`); or decode the largest
bin_table_init caller FDE `0x63cba10` (10 sites). Packet #269
should pick one of these, not both, to stay light.
