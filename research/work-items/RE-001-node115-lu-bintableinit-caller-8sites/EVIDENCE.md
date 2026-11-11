# RE-001-node115-lu-bintableinit-caller-8sites: second bin_table_init caller FDE

- Component ID: lu bin_table_init caller FDE 0x63c9c80..0x63cb146
- Target release and full SHA-256: node #115,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
  (105,896,032 bytes, artifacts/node/115/hl-node)
- Source commit / reference commit: upstream main
  05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly-backed) / inference (entry
  contract, walk roles) / unresolved (callee internals, runtime values)
- Scope included and excluded: included — the single FDE
  0x63c9c80..0x63cb146, its 21 calls, its 3 canary-checked
  tail-jump epilogues, its list phase and radix walks. Excluded —
  callee FDE internals, the 107 remaining static leaves, runtime
  .bss values, the next caller FDE 0x63ce8c0.

## Reproduce

Worktree ~/workspace/hl-wt-calls276-115 at upstream main 05bc2de30.
Static analysis only; the binary was never executed.

- `objdump -d --start-address=0x63c9c80 --stop-address=0x63cb146
  artifacts/node/115/hl-node` → 1179 strict lines (address +
  bytes + tab + lowercase mnemonic; byte-continuation lines
  excluded), stored as bintableinit_caller_8sites.objdump.txt.
- Raw bytes: binary slice at file offset VA - 0x1000, stored as
  bintableinit_caller_8sites.hex (5318 bytes, raw binary, not
  hex text).
- `python3 tools/node115_lu_bintableinit_caller_8sites.py` → exit 0.
- `python3 tests/test_node115_lu_bintableinit_caller_8sites.py`
  → 9/9 pass, tamper controls first.
- `make verify` → exit 0 (559 manifests, 7161 entries).
- `make catalogue-check` → exit 2, pre-existing Stale catalogue
  README.md on the new base (no catalogue file touched).
- Full `make test` NOT attempted (584 test files; no tally claimed).

## Evidence

Coordinates: virtual addresses as shown by objdump; .text file
offset = VA - 0x1000; .data = VA - 0x3000; .rodata = VA as-is.
FDE bounds from .eh_frame (PC-relative sdata4, fixed 4-byte
range fields): the FDE record at .eh_frame offset 0x392d74
gives initial_location 0x63c9c80, range 0x14c6 (5318 bytes).
Next FDE 0x63cb150 (padding 10); previous FDE 0x63c9650..
0x63c9c80 (gap 0).

Entry: six pushes, sub $0x838,%rsp, canary %fs:0x28 stored at
0x828(%rsp). rdi → rbp (context, radix root at +0x1b0), rsi →
rbx (key descriptor: +0x8 compared in list phase, +0x18 radix
key, +0x40 passed to 0x63d3080). Global pointer at 0x67144a0
loaded into stack temp 0x20(%rsp) (= r12) and stored back at
walk exits.

Call census (objdump mnemonic, 21 total): bin_table_init
0x63d9880 ×8 (all rdi = r12, all from rbp == 0 branches),
lu-miss 0x63d9700 ×8 (rdi = rbp, rsi = lea 0x6511a00, rdx =
node, rcx = key, r8 = 1, r9 = 0), 0x63637f0 ×1 call + ×1 tail
jump, 0x63bd6c0 ×1 call + ×1 tail jump, 0x6363260 ×1 call +
×1 tail jump, 0x63d3080 ×1 call (rbp, rbx+0x40),
__stack_chk_fail ×1 call (shared target 0x63cb0e5). No `ret`
in the FDE.

Radix walk markers (verified by grep over the exhibit):
shr $0x1a + and $0xf0 (top index), shr $0x9 + and $0x1ffff8
(second level), lea 0x65096c0 (leaf table), lea 0x6727a00
(second table), shr $0x30 + cmp $0x23 (deep-walk gate),
`lock sub` on struct+0x38 ×2 (refcount).

Raw-e8 census for target 0x63d9880 over all .eh_frame FDE
ranges: #275 FDE 0x63cba10 → 10, this FDE → 8, next highest
→ 6 (FDEs 0x63ce8c0 and 0x63d4bbe). Raw counts are upper
bounds on real calls, so second place by sites is strict.

## Implementation and comparison

Not yet implemented/measured. No Rust reconstruction is claimed
for this FDE; the packet is evidence only. Normalization masks:
objdump header lines stripped for regeneration comparison;
instruction-level comparisons use mnemonic + operands with
addresses stripped where noted. No helper/data/relocation
closure beyond the .rela.dyn-independent static reads above.

## Results and limitations

- Claimed: the FDE window, its call census and arg patterns,
  its list phase, its radix walk skeleton, its 3 tail-jump
  epilogues, its 10-byte next padding and 0-byte prev gap.
- Not claimed: callee internals, runtime .bss values, whether
  the radix root at rbp+0x1b0 belongs to one named structure,
  the next caller FDE 0x63ce8c0.
- Next question: decode the next bin_table_init caller FDE
  0x63ce8c0 (6 raw candidates); or open the next leaf family
  outside opt children. Packet #277 should pick one, not both.
