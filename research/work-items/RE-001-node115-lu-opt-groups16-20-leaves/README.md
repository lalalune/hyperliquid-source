# RE-001-node115-lu-opt-groups16-20-leaves

Node-115-only light packet: five more control-tree leaves classified
in tree order after packet #265's five hpa_sec leaves
(opt/metadata_thp, opt/retain, opt/dss, opt/narenas,
opt/percpu_arena). This packet takes packet #265's first
next-question option only; the largest bin_table_init caller FDE
`0x63cba10` (10 sites) is explicitly NOT decoded here, per #265's
"pick one, not both".

## Leaves (5 of the 151 remaining at packet start)

All five handlers are reached only by dispatcher indirect
tail-call: a whole-`.text` E8 census gives 0 direct entries per
leaf. Each handler's node+0x20 slot was confirmed via `.rela.dyn`
addends (60,723 `.rela.dyn` entries total, 59,534 of type RELATIVE;
file slots are zero-filled, so the addend is the authority), and
each node+0x08 name addend resolves to the leaf name below. The
five are the opt node's children-array groups 16–20 (array
`0x64de2e0`, 65 children, 5-qword entries, handler slot at entry
offset +32), in tree order after packet #265's
opt/hpa_sec_batch_fill_extra. FDE bounds come from `.eh_frame`
(PC-relative sdata4 encoding), not from endbr64 scanning.

Unlike packets #264/#265, this batch is mixed-shape, not one
template: two indexed-u64 leaves, one byte leaf, one plain-u64
leaf, and one u32 leaf. All five share the same contract skeleton
(the same shape as packet #261's value leaves): a write attempt
(newp|newlen != 0) returns 1 without touching memory; a read with
oldp==0 or oldlenp==0 returns 0; a read with *oldlenp==size stores
the value and returns 0; any other *oldlenp takes the short-read
path (n = min(*oldlenp, size) bytes copied from a stack temp,
*oldlenp set to n, return 0x16). Single ret per FDE; all jumps
stay inside the FDE; the only out-of-FDE transfer is the
`__stack_chk_fail` call on canary mismatch.

| leaf | node | handler FDE | value | file value |
| ---- | ---- | ----------- | ----- | ---------- |
| opt/metadata_thp | 0x64de560 | 0x6370480..0x637068d | u64 at .data 0x64ffbd0 + dword at .bss 0x6711b34 * 8 | index runtime (not in file) |
| opt/retain | 0x64de588 | 0x6370690..0x6370716 | byte at .data 0x64ffc28 | 1 |
| opt/dss | 0x64de5b0 | 0x6370720..0x6370937 | u64 at .data 0x64ffc20 | 0x0 |
| opt/narenas | 0x64de5d8 | 0x6370940..0x6370af3 | u32 at .bss 0x6511734 | runtime (not in file) |
| opt/percpu_arena | 0x64de600 | 0x6370b00..0x6370d0d | u64 at .data 0x64ffba0 + dword at .data 0x64ffb80 * 8 | index file-initial 2 |

File-initial values only: `.data` is writable, so runtime values
may differ; `.bss` values are not in the file at all. The two
indexed leaves load their value as table[index]: metadata_thp
reads its index dword from `.bss` `0x6711b34` and its table base
from `.data` `0x64ffbd0`; percpu_arena reads its index dword
from `.data` `0x64ffb80` (file-initial 2) and its table base from
`.data` `0x64ffba0`. The selected table entry therefore depends
on a runtime index and is not pinned to a single file value.
After this packet, 146 of the 204 static leaves remain
unclassified.

## Exhibits (5 windows, 2154 bytes, 597 strict lines)

Strict = address + bytes field + tab + mnemonic starting with a
lowercase letter; objdump byte-continuation lines excluded.

| exhibit | range | bytes | strict |
| ------- | ----- | ----- | ------ |
| metadata_thp | 0x6370480..0x637068d | 525 | 149 |
| retain | 0x6370690..0x6370716 | 134 | 36 |
| dss | 0x6370720..0x6370937 | 535 | 147 |
| narenas | 0x6370940..0x6370af3 | 435 | 116 |
| percpu_arena | 0x6370b00..0x6370d0d | 525 | 149 |

FDE paddings to the next FDE: metadata_thp 3 bytes (int3),
retain 10 bytes (int3), dss 9 bytes (int3), narenas 13 bytes,
percpu_arena 3 bytes to the next FDE at `0x6370d10` (group 21,
not claimed).

## Verification

- `tools/node115_lu_opt_groups16_20_leaves.py` exit 0 (byte reads
  only; never executes the binary).
- `tests/test_node115_lu_opt_groups16_20_leaves.py` standalone,
  including regeneration comparison, independent strict recount,
  and tamper controls run first (hex flip, strict-count change,
  injected overlap — each confirmed to fail the verifier, and a
  clean temp copy confirmed to pass).
- `make verify` exit 0 (see body for the tally).
- `make catalogue-check`: pre-existing `Stale catalogue:
  README.md` failure on the new base — not a packet regression,
  and not claimed as passing.
- Full `make test` is NOT attempted: 584 test files on the new
  base take hours and risk a VM-restart kill mid-run; no
  full-suite tally is claimed.
- MANIFEST.sha256 verified with sha256sum -c.

## Disjointness

The verifier's collector scans the merged tree plus prior worktree
records (#183-#265), deduplicated by real packet slug, and gathers
ONLY exhibited windows: string range fields, [start, end] lists
(hex strings or int pairs), and start/end pairs inside exhibits
lists or dicts, and windows lists or dicts. It never collects
enclosing-fde annotation fields (packet #259 lesson) and never
collects census/cited-only metadata subtrees (packet #253
lesson). All 5 windows are disjoint from every prior claimed
range, from packet #232's merged FDE `0x63b8820..0x63b8d85`
(checked explicitly), from packet #252's r28_wait window
`0x63ec890..0x63ec8a3`, from packet #215's handler FDE
`0x63d9700..0x63d987b`, and from each other. The slug
RE-001-node115-lu-opt-groups16-20-leaves does not collide with
any merged-tree directory.

## Not covered (explicit)

- The remaining 146 static leaves.
- The getter family and dispatcher internals beyond the leaf
  contract.
- Runtime values of `.bss` globals `0x6711b34` and `0x6511734`,
  and runtime values of `.data` globals `0x64ffc28`, `0x64ffc20`,
  `0x64ffb80` (only file-initial values are reported).
- The largest bin_table_init caller FDE `0x63cba10` (10 sites):
  not decoded (packet #265's other option, explicitly not taken
  here).
- Packet #265's framings are NOT corrected or re-claimed here;
  nothing in this packet's disassembly contradicts them.

## Next question

Classify the next five leaves in tree order (opt children groups
21+, starting with the FDE at `0x6370d10`); or decode the largest
bin_table_init caller FDE `0x63cba10` (10 sites). Packet #267
should pick one of these, not both, to stay light.
