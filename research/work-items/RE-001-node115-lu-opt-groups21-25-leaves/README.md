# RE-001-node115-lu-opt-groups21-25-leaves

Node-115-only light packet: five more control-tree leaves classified
in tree order after packet #266's five groups 16–20 leaves
(opt/oversize_threshold, opt/mutex_max_spin, opt/background_thread,
opt/max_background_threads, opt/dirty_decay_ms), all read-only.
This packet takes packet #266's first next-question option only;
the largest bin_table_init caller FDE `0x63cba10` (10 sites) is
explicitly NOT decoded here, per #266's "pick one, not both".

## Leaves (5 of the 146 remaining at packet start)

All five handlers are reached only by dispatcher indirect
tail-call: a whole-`.text` E8 census gives 0 direct entries per
leaf. Each handler's node+0x20 slot was confirmed via `.rela.dyn`
addends (60,723 `.rela.dyn` entries total, 59,534 of type
RELATIVE; file slots are zero-filled, so the addend is the
authority), and each node+0x08 name addend resolves to the leaf
name below. The five are the opt node's children-array groups
21–25 (array `0x64de2e0`, 65 children, 5-qword entries, handler
slot at entry offset +32), in tree order after packet #266's
opt/percpu_arena. FDE bounds come from `.eh_frame`
(PC-relative sdata4 encoding), not from endbr64 scanning.

Tree order is node order, not address order: group 21's handler
(`0x6370f30`) sits after group 22's (`0x6370d10`) in address
order. Packet #266's next question ("starting with the FDE at
`0x6370d10`") names the lowest address among the five, which is
group 22's handler; group 21 is not skipped — it is the first
leaf below, in node order.

This batch is mixed-shape like packet #266's, not one template:
four plain-u64 leaves and one byte leaf. All five share the same
contract skeleton (the same shape as packet #261's value leaves):
a write attempt (newp|newlen != 0) returns 1 without touching
memory; a read with oldp==0 or oldlenp==0 returns 0; a read with
*oldlenp==size stores the value and returns 0; any other
*oldlenp takes the short-read path (n = min(*oldlenp, size)
bytes copied from a stack temp, *oldlenp set to n, return 0x16).
Single ret per FDE; all jumps stay inside the FDE; the only
out-of-FDE transfer is the `__stack_chk_fail` call on canary
mismatch.

| leaf | node | handler FDE | value | file value |
| ---- | ---- | ----------- | ----- | ---------- |
| opt/oversize_threshold | 0x64de628 | 0x6370f30..0x6371147 | u64 at .data 0x64ffb70 | 0x800000 (8388608) |
| opt/mutex_max_spin | 0x64de650 | 0x6370d10..0x6370f27 | u64 at .data 0x64ffc98 | 0x258 (600) |
| opt/background_thread | 0x64de678 | 0x6371150..0x63711d6 | byte at .bss 0x6711b30 | runtime (not in file) |
| opt/max_background_threads | 0x64de6a0 | 0x63711e0..0x63713f7 | u64 at .data 0x64ffbc8 | 0x1000 (4096) |
| opt/dirty_decay_ms | 0x64de6c8 | 0x6371400..0x6371617 | u64 at .data 0x64ffb78 | 0x2710 (10000) |

File-initial values only: `.data` is writable, so runtime values
may differ; `.bss` values are not in the file at all. The four
u64 FDEs are instruction-identical modulo the value-load lea
displacement and intra-FDE jump targets (verified by a
normalized instruction-level diff, whose only difference is the
lea line). After this packet, 141 of the 204 static leaves remain
unclassified.

## Exhibits (5 windows, 2274 bytes, 624 strict lines)

Strict = address + bytes field + tab + mnemonic starting with a
lowercase letter; objdump byte-continuation lines excluded.

| exhibit | range | bytes | strict |
| ------- | ----- | ----- | ------ |
| oversize_threshold | `0x6370f30..0x6371147` | 535 | 147 |
| mutex_max_spin | `0x6370d10..0x6370f27` | 535 | 147 |
| background_thread | `0x6371150..0x63711d6` | 134 | 36 |
| max_background_threads | `0x63711e0..0x63713f7` | 535 | 147 |
| dirty_decay_ms | `0x6371400..0x6371617` | 535 | 147 |

Paddings to the next FDE: mutex_max_spin → oversize_threshold
9 bytes, oversize_threshold → background_thread 9 bytes,
background_thread → max_background_threads 10 bytes,
max_background_threads → dirty_decay_ms 9 bytes,
dirty_decay_ms → next FDE `0x6371620` (group 26, not claimed)
9 bytes.

## Verification

- Static verifier `tools/node115_lu_opt_groups21_25_leaves.py`
  (byte reads only; never executes the binary): exit 0.
- Own unit tests `tests/test_node115_lu_opt_groups21_25_leaves.py`:
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
worktree records (#183–#266), deduplicated by real packet slug,
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
other. The slug `RE-001-node115-lu-opt-groups21-25-leaves` does
not collide with any merged-tree directory.

## Not covered (explicit)

- The remaining 141 static leaves.
- The getter family and dispatcher internals beyond the leaf
  contract.
- Runtime values of the `.bss` byte at `0x6711b30` and runtime
  values of the `.data` qwords (only file-initial values are
  reported).
- The largest bin_table_init caller FDE `0x63cba10` (10 sites):
  not decoded (packet #266's other option, explicitly not taken
  here).
- Packet #266's framings are NOT corrected or re-claimed here;
  nothing in this packet's disassembly contradicts them.

## Next question

Classify the next five leaves in tree order (opt children groups
26+, starting with the FDE at `0x6371620`); or decode the largest
bin_table_init caller FDE `0x63cba10` (10 sites). Packet #268
should pick one of these, not both, to stay light.
