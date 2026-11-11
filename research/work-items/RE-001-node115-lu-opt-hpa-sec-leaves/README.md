# RE-001 node-115: opt hpa_sec leaves (groups 11–15)

Packet #265 in the RE-001 node-115 leaf-classification chain, answering
packet #264's first next question. It classifies 5 more control-tree
leaves in tree order after packet #264's five hpa leaves, all read-only
u64 value leaves sharing one contract template. This packet takes
packet #264's first next-question option only; the largest
bin_table_init caller FDE `0x63cba10` (10 sites) is explicitly NOT
decoded here, per #264's "pick one, not both".

Target: node #115, `artifacts/node/115/hl-node` (105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`),
upstream main `05bc2de303c05525b71e7e257426e741bc66a390`. Static
analysis only; the binary was never executed. `.hex` exhibit files
contain raw binary bytes, not hex text.

## Leaves classified here (5, all read-only)

Leaves were resolved as the opt node's children-array groups 11–15
(array `0x64de2e0`, 65 children, 5-qword entries, handler slot at
entry offset +32). Each handler's node+0x20 slot was confirmed via
`.rela.dyn` RELATIVE addends (file slots are zero-filled, so the
addend is the authority), and each node+0x08 name addend resolves to
the leaf name below. All 5 handlers are reached only by dispatcher
indirect tail-call: a whole-`.text` E8 census gives 0 direct entries
per leaf. FDE bounds come from `.eh_frame` (PC-relative sdata4
encoding), not from endbr64 scanning. All five FDEs are 535 bytes
with 147 strict instructions each, consecutive with 9 bytes of
padding between neighbours.

All five share one read-only contract (the same shape as packet
#261's value leaves and packet #264's hpa leaves): a write attempt
(newp|newlen != 0) returns 1 without touching memory; a read with
oldp==0 or oldlenp==0 returns 0; a read with *oldlenp==8 stores the
value and returns 0; any other *oldlenp takes the short-read path
(n = min(*oldlenp, 8) bytes copied from a stack temp, *oldlenp set
to n, return 0x16). The five differ only in the `.data` qword they
read, all in one contiguous struct at `0x64ffac0`:

| leaf | node | handler FDE | value | file value |
| ---- | ---- | ----------- | ----- | ---------- |
| opt/hpa_sec_nshards | 0x64de498 | 0x636f9e0..0x636fbf7 | u64 at .data 0x64ffac0 | 0x4 (4) |
| opt/hpa_sec_max_alloc | 0x64de4c0 | 0x636fc00..0x636fe17 | u64 at .data 0x64ffac8 | 0x8000 (32768) |
| opt/hpa_sec_max_bytes | 0x64de4e8 | 0x636fe20..0x6370037 | u64 at .data 0x64ffad0 | 0x40000 (262144) |
| opt/hpa_sec_bytes_after_flush | 0x64de510 | 0x6370040..0x6370257 | u64 at .data 0x64ffad8 | 0x20000 (131072) |
| opt/hpa_sec_batch_fill_extra | 0x64de538 | 0x6370260..0x6370477 | u64 at .data 0x64ffae0 | 0x0 (0) |

File-initial values only: `.data` is writable, so runtime values may
differ. After this packet, 151 of the 204 static leaves remain
unclassified.

Entry shape (identical across all five, modulo the struct offset in
the value load): endbr64, stack frame setup, stack-canary save,
r11d preset to 1, `or 0x20(%rsp),%r9` (newlen|newp) branching to the
return-1 epilogue on nonzero, then the value load (`mov
<off>(%rdx),%rdi` from base `0x64ffac0`), the exact-read store on
*oldlenp==8, and the short-read copy loop ending in `*oldlenp := n`
and return 0x16. Single ret per FDE; all jumps stay inside the FDE
(the only out-of-FDE control transfer is the `__stack_chk_fail`
call on canary mismatch).

## Verification

- Static verifier `tools/node115_lu_opt_hpa_sec_leaves.py` (byte
  reads only; never executes the binary): exit 0.
- Own unit tests `tests/test_node115_lu_opt_hpa_sec_leaves.py`:
  standalone, including regeneration comparison, independent strict
  recount, and tamper controls run first (hex flip, strict-count
  change, injected overlap — each confirmed to fail the verifier,
  and a clean temp copy confirmed to pass).
- `make verify`: exit 0 (559 evidence-packet manifests, 7169
  entries — actual tally, not copied: base 7154 + this packet's 15
  MANIFEST entries).
- `make catalogue-check`: exit 2, pre-existing `Stale catalogue:
  README.md` on the new base (verified: no catalogue file is touched
  by this packet; only the packet dir, tools file, and tests file are
  added) — not a packet regression, and not claimed as passing.
- Full `make test` is NOT attempted: 584 test files on the new base
  take hours and risk a VM-restart kill mid-run; no full-suite tally
  is claimed.
- MANIFEST.sha256 verified with `sha256sum -c` (all 15 entries OK).

## Disjointness

The verifier's collector scans the merged tree plus prior worktree
records (#183–#264), deduplicated by real packet slug, and gathers
ONLY exhibited windows: string range fields, [start, end] lists (hex
strings or int pairs), and start/end pairs inside exhibits lists or
dicts, and windows lists or dicts. It never collects enclosing-fde
annotation fields (packet #259 lesson) and never collects
census/cited-only metadata subtrees (packet #253 lesson). All 5
windows are disjoint from every prior claimed range, from packet
#232's merged FDE `0x63b8820..0x63b8d85` (checked explicitly), from
packet #252's r28_wait window `0x63ec890..0x63ec8a3`, from packet
#215's handler FDE `0x63d9700..0x63d987b`, and from each other. The
slug `RE-001-node115-lu-opt-hpa-sec-leaves` does not collide with
any merged-tree directory.

## Not covered (explicit)

- The remaining 151 static leaves.
- The getter family and dispatcher internals beyond the leaf
  contract.
- Runtime values of the `.data` globals at `0x64ffac0..0x64ffae0`
  (only file-initial values are reported).
- The largest bin_table_init caller FDE `0x63cba10` (10 sites):
  not decoded (packet #264's other option, explicitly not taken
  here).

## Next question (#266)

Classify the next five leaves in tree order (opt children groups
16+, starting with metadata_thp handler `0x6370480` and retain
handler `0x6370690`); or decode the largest bin_table_init caller
FDE `0x63cba10` (10 sites). Packet #266 should pick one of these,
not both, to stay light.
