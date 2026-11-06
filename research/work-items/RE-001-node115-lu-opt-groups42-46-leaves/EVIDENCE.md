# RE-001-node115-lu-opt-groups42-46-leaves: classify opt children groups 42–46

- Component ID: lu opt control-tree leaves (groups 42–46)
- Target release and full SHA-256: node #115, artifacts/node/115/hl-node, 105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: upstream main 05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly + file bytes); runtime values unresolved where noted
- Scope included and excluded: five leaf handlers only (groups 42–46). Excluded: the largest bin_table_init caller FDE 0x63cba10, the getter family, dispatcher internals beyond the leaf contract, group 47+.

## Reproduce

Working directory: the worktree root. Binary path: artifacts/node/115/hl-node.
Tools: objdump (binutils), readelf, python3, sha256sum. No execution of the
binary anywhere; all checks are byte reads and disassembly.

- `sha256sum artifacts/node/115/hl-node` → a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- `python3 tools/node115_lu_opt_groups42_46_leaves.py` → exit 0
- `python3 tests/test_node115_lu_opt_groups42_46_leaves.py` → standalone, tamper controls first
- `make verify` → exit 0 (559 evidence-packet manifests, 7169 entries)
- `make catalogue-check` → exit 2, pre-existing Stale catalogue: README.md (not a packet regression)
- Full `make test` NOT attempted (584 test files on the new base).

## Evidence

Coordinate system: .text file offset = VA − 0x1000 (re-derived from program
headers: PT_LOAD off=0x1418300 ↔ vaddr=0x1419300); .data.rel.ro/.got =
VA − 0x2000; .rodata = VA as-is; .data = VA − 0x3000. RELATIVE .got slots
are zero-filled in the file, so GOT census uses .rela.dyn addends (60,723
entries total, 59,534 of type RELATIVE).

Opt children array: base 0x64de2e0, 65 children, 5-qword entries, handler
slot at entry offset +32, name slot at entry offset +8. Node address =
array base + group × 40. FDE bounds from .eh_frame (PC-relative sdata4,
fixed 4-byte range fields — a ULEB parse cuts handlers mid-instruction,
packet #270 lesson).

| group | node | name addend → name | handler slot → FDE |
| ----- | ---- | ------------------ | ------------------ |
| 42 | 0x64de970 | opt/tcache_gc_incr_bytes | 0x6372bd0..0x6372de7 (535B/147) |
| 43 | 0x64de998 | opt/tcache_gc_delay_bytes | 0x6372df0..0x6373007 (535B/147) |
| 44 | 0x64de9c0 | opt/lg_tcache_flush_small_div | 0x6373010..0x63731c3 (435B/116) |
| 45 | 0x64de9e8 | opt/lg_tcache_flush_large_div | 0x63731d0..0x6373383 (435B/116) |
| 46 | 0x64dea10 | opt/thp | 0x6373390..0x637359d (525B/149) |

Value mechanism per leaf (all share the #261 contract skeleton: write →
1, oldp==0/oldlenp==0 → 0, exact-length read stores value → 0, short
read → min copy, *oldlenp := n, 0x16):

- tcache_gc_incr_bytes: lea → .data 0x64ffdd0; mov (%rdx),%rdi (u64);
  cmp $0x8,%rcx; file value 0x10000.
- tcache_gc_delay_bytes: lea → .bss 0x6728870; mov (%rdx),%rdi (u64);
  cmp $0x8,%rcx; runtime value (not in file).
- lg_tcache_flush_small_div: lea → .data 0x64ffdcc; mov (%rdx),%esi
  (u32); cmp $0x4,%rcx; file value 0x1.
- lg_tcache_flush_large_div: lea → .data 0x64ffdc8; mov (%rdx),%esi
  (u32); cmp $0x4,%rcx; file value 0x1.
- thp: lea → .bss 0x6712378 (index); mov (%rdx),%ecx (u32 index);
  lea → .data 0x64ffcc0 (table base); mov (%rsi,%rcx,8),%rdi (u64
  table entry); cmp $0x8,%rcx. Returned value is runtime-determined.
  File-initial table entries at indices 4–8: 0x1, 0xffffffffffffffff,
  0x13, 0x101, 0xffffffffffffffff.

Structural invariants (all five): exactly 1 ret; exactly 1 call, to
`__stack_chk_fail` PLT 0x63f0d70; all jump targets inside the FDE;
whole-`.text` raw E8 census gives 0 direct entries per handler. The two
u64 FDEs are instruction-identical modulo the value-load lea
displacement and intra-FDE jump targets, as are the two u32 FDEs
(verified by a normalized instruction-level diff).

Paddings to the next FDE: 9, 9, 13, 13, 3 bytes respectively; next FDE
after the last is 0x63735a0 (group 47, not claimed).

Disjointness: range-only collector over the merged tree plus packets
#183–#270 worktrees, deduplicated by real packet slug, census/cited-only
subtrees excluded; explicit non-overlap checks against packet #232
(0x63b8820..0x63b8d85), packet #252 r28_wait (0x63ec890..0x63ec8a3),
packet #215 (0x63d9700..0x63d987b), packet #261 group-36 tcache
(0x63721c0..0x6372246). Group 42's handler is exactly packet #270's
next-question FDE, verified unclaimed before building.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction in this packet; it
is an evidence packet only (exhibits + static verifier + tests).

## Results and limitations

- Classified: 5 leaves (groups 42–46). Remaining unclassified: 121 of
  the 204 static leaves.
- Unknown: runtime values of .bss 0x6728870 and .bss index 0x6712378;
  runtime values of .data slots; which table entry thp returns for any
  particular runtime index; whether the value slots belong to one struct.
- Not decoded: largest bin_table_init caller FDE 0x63cba10 (10 sites),
  getter family, dispatcher internals beyond the leaf contract.
- Next question: classify the next five leaves in tree order (opt
  children groups 47+, starting with the FDE at 0x63735a0); or decode
  the largest bin_table_init caller FDE 0x63cba10 (10 sites). Packet
  #272 should pick one of these, not both, to stay light.
