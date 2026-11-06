# RE-001-node115-lu-opt-groups37-41-leaves: evidence

- Component ID: lu opt control-tree leaves, groups 37–41 (group 36 skipped
  as already claimed by packet #261)
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`,
  105,896,032 bytes,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: observation (disassembly + file bytes only; no execution)
- Scope included and excluded: the five handler FDEs listed in README.md
  only. Group 36 (opt/tcache) is excluded because packet #261 (PR #2804)
  already claims it. Dispatcher internals, the getter family, runtime
  values, and the largest bin_table_init caller FDE 0x63cba10 are excluded.

## Reproduce

Working directory: the worktree root. Static analysis only; the node binary
is never executed.

```
objdump -d --start-address=0x6372250 --stop-address=0x6372467 artifacts/node/115/hl-node
objdump -d --start-address=0x6372470 --stop-address=0x6372623 artifacts/node/115/hl-node
objdump -d --start-address=0x6372630 --stop-address=0x63727e3 artifacts/node/115/hl-node
objdump -d --start-address=0x63727f0 --stop-address=0x63729a3 artifacts/node/115/hl-node
objdump -d --start-address=0x63729b0 --stop-address=0x6372bc7 artifacts/node/115/hl-node
python3 tools/node115_lu_opt_groups37_41_leaves.py   # exit 0
python3 tests/test_node115_lu_opt_groups37_41_leaves.py  # standalone
```

## Evidence

Coordinate system: `.text` file offset = VA − 0x1000 (program headers:
PT_LOAD off=0x1418300 ↔ vaddr=0x1419300); `.data` file offset = VA − 0x3000
(section .data VA 0x64efa20, file offset 0x64eca20); `.rodata` VA as-is;
`.data.rel.ro`/`.got` VA − 0x2000. FDE bounds from `.eh_frame` (CIE
augmentation zR, encoding 0x1b = pcrel + sdata4; the range field is a fixed
4-byte value, not ULEB — an early ULEB parse cut two handlers
mid-instruction and was fixed before any exhibit was generated).

Leaf resolution: each handler's node+0x20 slot and node+0x08 name slot were
confirmed via `.rela.dyn` addends (60,723 entries total, 59,534 of type
RELATIVE; file slots are zero-filled, so the addend is the authority).
Opt children array 0x64de2e0, 65 children, 5-qword entries, handler slot at
entry offset +32. Node order defines the sequence (packet #267's lesson);
here node order and address order agree.

| leaf | node | handler FDE | value slot | file value |
| ---- | ---- | ----------- | ---------- | ---------- |
| opt/tcache_max | 0x64de8a8 | 0x6372250..0x6372467 | qword at .data 0x64ffdf0 | 0x8000 |
| opt/tcache_nslots_small_min | 0x64de8d0 | 0x6372470..0x6372623 | u32 at .data 0x64ffde8 | 0x14 |
| opt/tcache_nslots_small_max | 0x64de8f8 | 0x6372630..0x63727e3 | u32 at .data 0x64ffde4 | 0xc8 |
| opt/tcache_nslots_large | 0x64de920 | 0x63727f0..0x63729a3 | u32 at .data 0x64ffde0 | 0x14 |
| opt/lg_tcache_nslots_mul | 0x64de948 | 0x63729b0..0x6372bc7 | qword at .data 0x64ffdd8 | 0x1 |

Contract observed in each FDE (same skeleton as packet #261's value
leaves): `or 0x20(%rsp),%r9` on the newp|newlen arguments — nonzero jumps
to the return-1 path without touching memory; oldp==0 or oldlenp==0
returns 0; *oldlenp==size stores the value (qword / u32 per leaf) and
returns 0; any other *oldlenp takes the short-read path (n = min(*oldlenp,
size) bytes copied from a stack temp, *oldlenp set to n, return 0x16).
Each FDE has exactly 1 ret and exactly 1 call, the `__stack_chk_fail` PLT
call at 0x63f0d70 on canary mismatch; all jumps stay inside the FDE. A
whole-`.text` raw E8 census gives 0 direct entries per handler (handlers
are reached only by dispatcher indirect tail-call).

The three u32 FDEs are instruction-identical modulo the value-load lea
displacement and intra-FDE jump targets (normalized instruction-level
diff: 116 lines each; the normalizer strips the full lea comment, whose
nearest-symbol suffix differs per target, and reduces jump lines to
mnemonic + TARGET). The five value slots are adjacent (0x64ffdd8,
0x64ffde0, 0x64ffde4, 0x64ffde8, 0x64ffdf0); whether they form one struct
is NOT proven.

Group-36 skip proof: packet #261's records
(`RE-001-node115-lu-value-leaves-bin`, PR #2804) list exhibit `opt_tcache`
with range 0x63721c0..0x6372246 and leaf `opt/tcache` at node 0x64de880
with value "global byte 0x64ffdf8" — the exact window, node, and slot this
packet's draft first claimed. The draft was dropped and rebuilt as groups
37–41; the verifier's disjointness check now passes with no overlap, and
group 36 is explicitly not claimed here.

Raw exhibits beside this record: per-leaf `.hex` (raw binary bytes, not
hex text) and `.objdump.txt` files, plus `records.json` and
`MANIFEST.sha256`.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is attempted here;
this packet is observation only. The static verifier
`tools/node115_lu_opt_groups37_41_leaves.py` re-derives every claim from
the binary (FDE bounds, `.rela.dyn` slots and names, value-load lea
targets, `.data` file values, contract markers, single-ret counts, jump
containment, calls-only-`__stack_chk_fail`, whole-`.text` E8 census,
disjointness including the explicit group-36 exclusion, MANIFEST hashes)
and fails on any mismatch; the unit tests regenerate the exhibits and run
tamper controls first.

## Results and limitations

- Claimed: 5 windows, 2375 bytes, 642 strict instructions; all checks
  pass (verifier exit 0; own tests standalone; `make verify` exit 0).
- `make catalogue-check` exits 2 with pre-existing `Stale catalogue:
  README.md` on the new base — not a packet regression, not claimed as
  passing. Full `make test` is NOT attempted (584 test files).
- Unknown: runtime values of the five `.data` slots; whether the five
  adjacent slots form one struct; dispatcher internals and the getter
  family; the largest bin_table_init caller FDE 0x63cba10.
- Next question: classify opt children groups 42+ (starting with the FDE
  at 0x6372bd0 — opt/tcache_gc_incr_bytes, group 42, node 0x64de970); or
  decode the largest bin_table_init caller FDE 0x63cba10 (10 sites).
  Packet #271 should pick one, not both, to stay light.
