# RE-001-node115-lu-opt-groups61-64-leaves: final four opt children leaves

- Component ID: lu opt children groups 61–64 (opt/prof_sys_thread_name,
  opt/prof_time_resolution, opt/lg_san_uaf_align, opt/zero_realloc)
- Target release and full SHA-256: node #115,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
  (105,896,032 bytes, artifacts/node/115/hl-node)
- Source commit / reference commit: upstream main
  05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly + relocation + unwind data);
  value semantics inferred from the leaf contract skeleton shared with
  packet #261's value leaves; runtime values unresolved where noted
- Scope included and excluded: included — the four handler FDEs, their
  node slots, value slots/tables, paddings, and the index-65
  non-entry. Excluded — dispatcher internals, getter family, runtime
  values, the bin_table_init caller FDE 0x63cba10.

## Reproduce

Working directory: a worktree of upstream main
05bc2de303c05525b71e7e257426e741bc66a390. Static tools only
(readelf, objdump, python3); the binary is never executed.

- Node slots: `readelf -r artifacts/node/115/hl-node`, RELATIVE
  entries (59,534 total). Group nodes: 61 → 0x64dec68, 62 →
  0x64dec90, 63 → 0x64decb8, 64 → 0x64dece0; +0x08 name addends
  resolve to the leaf names, +0x20 handler addends resolve to
  the handler FDEs below.
- FDE bounds: `readelf --debug-dump=frames
  artifacts/node/115/hl-node` (PC-relative sdata4, fixed 4-byte
  range fields, not ULEB).
- Disassembly: `objdump -d --start-address=<start>
  --stop-address=<end> artifacts/node/115/hl-node` per window.
- Verifier: `python3 tools/node115_lu_opt_groups61_64_leaves.py`
  (exit 0, 81 PASS). Tests:
  `python3 tests/test_node115_lu_opt_groups61_64_leaves.py`
  (7/7, tamper controls first).

## Evidence

Coordinate system: virtual addresses as shown by objdump/readelf.
`.text` file offset = VA − 0x1000; `.data` file offset = VA −
0x3000; `.rodata` file offset = VA as-is; `.bss` has no file
bytes. `.rela.dyn` file slots are zero-filled, so addends are
the authority for node slots.

| leaf | node | handler FDE | bytes | strict | mechanism |
| ---- | ---- | ----------- | ----- | ------ | --------- |
| prof_sys_thread_name | 0x64dec68 | 0x6374540..0x63745c6 | 134 | 36 | byte leaf: lea # 67125f0, movzbl, size-1 contract |
| prof_time_resolution | 0x64dec90 | 0x63745d0..0x63747dd | 525 | 149 | indirect-table u64: u32 index at .bss 0x6712370, table .data 0x64ffca0, size 8 |
| lg_san_uaf_align | 0x64decb8 | 0x6378080..0x637808a | 10 | 3 | endbr64 + mov $0x2,%eax + ret; bytes f30f1efab802000000c3 |
| zero_realloc | 0x64dece0 | 0x63747e0..0x63749ed | 525 | 149 | indirect-table u64: u32 index at .data 0x64ffb58 (=1 in file), table .data 0x64ffb40, size 8 |

Raw disassembly and raw binary windows sit beside this record
as `<name>.objdump.txt` and `<name>.hex` (raw binary bytes,
not hex text). Whole-`.text` raw E8 scan: 0 direct call
candidates per handler. Each non-stub FDE has exactly 1 ret
and exactly 1 call (the `__stack_chk_fail` PLT at 0x63f0d70);
the stub has 1 ret and 0 calls. All jumps stay inside their
FDE. The two indirect-table FDEs are normalized-identical
modulo lea displacements and intra-FDE jump targets (149
lines each).

Opt-array exhaustion: entry 0x64ded08 (index 65) has no
+0x08 relocation and its +0x20 slot resolves to 0x43fce3
(`.rodata`), so it is not a node entry. Groups 0–15 handler
starts are each contained in a prior claimed window
(handler-start containment check over all prior exhibits);
groups 16–60 were classified by packets #266–#273.

Paddings: prof_sys_thread_name → prof_time_resolution 10;
prof_time_resolution → zero_realloc 3; lg_san_uaf_align →
xmalloc (#269) 6; zero_realloc → thread_allocated (#261) 3.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is
attempted in this packet. Comparison performed: normalized
instruction-level diff between the two indirect-table FDEs
(identical); byte comparison between the lg_san_uaf_align
stub and packet #269's xmalloc stub (identical).

## Results and limitations

- Static verifier: exit 0 (81 PASS, 0 FAIL), including
  disjointness against 1062 unique-slug prior ranges.
- Own tests: 7/7 pass; tamper controls (hex flip,
  strict-count change, injected overlap, value-slot lea
  change) each confirmed to fail the verifier.
- `make verify`: exit 0 (see README for the actual tally).
- `make catalogue-check`: exit 2, pre-existing Stale
  catalogue README.md on the new base; not a regression.
- Full `make test` NOT attempted (584 test files; hours
  of runtime, VM-restart risk); no full-suite tally claimed.
- Unknown: runtime values of all `.bss` slots and of the
  writable `.data` slots; whether adjacent index/table
  slots belong to one struct/table; the owner of any
  unclassified leaf outside the opt array.

Next question: the opt array is exhausted, so packet #275
must open a new family — decode the largest bin_table_init
caller FDE 0x63cba10 (10 sites), or open the next leaf
family outside opt children. Pick one, not both.
