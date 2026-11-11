# RE-001-node115-lu-opt-groups56-60-leaves: opt control-tree leaves 56-60

- Component ID: lu opt children-array leaves (jemalloc control tree)
- Target release and full SHA-256: node #115,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
  (105,896,032 bytes, artifacts/node/115/hl-node)
- Source commit / reference commit: upstream main
  05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly + relocation + unwind evidence)
- Scope included and excluded: five leaf handlers (groups 56-60) and
  their value slots; excluded: dispatcher internals, getter family,
  runtime values, the largest bin_table_init caller FDE 0x63cba10.

## Reproduce

Worktree at upstream main 05bc2de30; static analysis only, binary
never executed. Tools: readelf (relocations, section headers,
.eh_frame bounds), objdump -d with --start-address/--stop-address
per FDE window, python3 stdlib for range/strict arithmetic.
Coordinate system: .text file offset = VA - 0x1000 (program
headers PT_LOAD off=0x1418300 <-> vaddr=0x1419300);
.data.rel.ro/.got = VA - 0x2000; .rodata = VA as-is; .data =
VA - 0x3000. RELATIVE .got slots are zero-filled in the file, so
GOT census uses .rela.dyn addends (60,723 entries total, 59,534
of type RELATIVE). Node slots: opt children array 0x64de2e0,
65 children, 5-qword entries; handler slot at entry offset +32
(node+0x20), name slot at node+0x08. Strict counts are
mnemonic-line counts (address + bytes field + tab + mnemonic
starting with a lowercase letter; objdump byte-continuation
lines excluded), computed programmatically, never by hand.

## Evidence

Leaf table (node order = tree order; address order differs for
group 58, see README correction):

| leaf | node | handler FDE | bytes | strict | value slot |
| ---- | ---- | ----------- | ----- | ------ | ---------- |
| prof_leak | 0x64deba0 | 0x6374170..0x63741f6 | 134 | 36 | byte .bss 0x6713603 |
| prof_leak_error | 0x64debc8 | 0x6374200..0x6374286 | 134 | 36 | byte .bss 0x6713602 |
| prof_accum | 0x64debf0 | 0x6373da0..0x6373e26 | 134 | 36 | byte .bss 0x6713601 |
| prof_recent_alloc_max | 0x64dec18 | 0x6374290..0x63744a7 | 535 | 147 | qword .bss 0x6715910 |
| prof_stats | 0x64dec40 | 0x63744b0..0x6374536 | 134 | 36 | byte .bss 0x6717690 |

Totals: 1071 bytes, 291 strict instructions. Each FDE: exactly
1 ret, exactly 1 call (`__stack_chk_fail` PLT 0x63f0d70), all
jump targets inside the FDE, 0 direct E8 entries in a whole-
.text raw rel32 census. Byte leaves compare *oldlenp against
0x1 and copy via a scalar byte loop; the u64 leaf compares
against 0x8 and copies via an unrolled 8-byte path. All value
slots are .bss, so no file-initial values exist; only the
mechanism (slot address + size + contract) is claimed.
Adjacent .bss bytes 0x6713601-0x6713605 (accum, leak_error,
leak, prof_final, prof_gdump) are proximity only, not a proven
struct. Correction: packet #272's gap note claimed FDE
0x6373da0..0x6373e26 is not an opt child handler; the node
slot, name slot, .eh_frame bounds, and byte-leaf body prove it
is group 58 opt/prof_accum (see README for the full proof).
Raw exhibits (.hex = raw binary bytes, .objdump.txt) sit beside
this record; the verifier regenerates and re-counts them.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed
by this observation packet. The static verifier
(tools/node115_lu_opt_groups56_60_leaves.py) and its tests
(tests/test_node115_lu_opt_groups56_60_leaves.py) check binary
identity, exhibit bytes, objdump regeneration, strict recounts,
.eh_frame bounds, .rela.dyn name/handler slots, value-load
targets, contract structure, E8 census, disjointness, and
MANIFEST hashes. Tamper controls (hex flip, strict-count
change, injected overlap, value-slot change) each fail the
verifier; a clean temp copy (packet dir + tools + tests,
binary reused by path, not copied) passes.

## Results and limitations

Verifier exit 0; own tests all pass (tamper controls run first);
make verify exit 0 (559 evidence-packet manifests, 7169 entries
= base 7154 + this packet's 15); make catalogue-check exit 2,
pre-existing Stale catalogue: README.md on the new base, not a
packet regression and not claimed as passing; full make test
NOT attempted (584 test files, hours-long, VM-restart risk).
Unknown: runtime values of all five slots; dispatcher-side
meaning of returned values; whether adjacent slots form one
struct; the remaining 111 static leaves. Next question:
classify groups 61+ starting at FDE 0x6374540 (group 61
opt/prof_sys_thread_name, node 0x64dec68), or decode the
largest bin_table_init caller FDE 0x63cba10 — pick one, not
both, and verify every group in the window first.
