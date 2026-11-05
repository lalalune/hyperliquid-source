# RE-001-node115-lu-bintableinit-caller-2sites-walk-10rsp: bounded question

- Component ID: RE-001-node115-lu-bintableinit-caller-2sites-walk-10rsp
- Target release and full SHA-256: node #115, artifacts/node/115/hl-node, 105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: upstream main 05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly + byte census); the walk/scans/lock-add/gate are decoded from the objdump exhibit, not from runtime observation
- Scope included and excluded: included — FDE 0x636b940..0x636bd90 only (1104 bytes), its two bin_table_init sites, two lu-miss sites, gate/size-class block, scans, lock add, single ret exit. Excluded — bin_table_init body, lu-miss handler body, helper 0x6364880 body, neighboring FDEs, runtime values of any .bss byte.

## Reproduce

Working directory: the worktree root (hl-wt-calls290-115). Static reads only; the target binary is never executed.

- `objdump -d --start-address=0x636b940 --stop-address=0x636bd90 artifacts/node/115/hl-node` → exhibits/bintableinit_caller_walk_10rsp_2sites.objdump.txt (228 strict lines).
- Raw bytes: file offset = VA - 0x1000 → exhibits/bintableinit_caller_walk_10rsp_2sites.hex (1104 raw binary bytes, not hex text).
- `python3 tools/node115_lu_bintableinit_caller_walk_10rsp_2sites.py` → exit 0 (see Verification in README).
- `python3 tests/test_node115_lu_bintableinit_caller_walk_10rsp_2sites.py` → exit 0, 17 checks (tamper controls first).
- `make verify` → exit 0; `make catalogue-check` → exit 2, pre-existing Stale catalogue: README.md on the new base (not a packet regression). Full `make test` is NOT attempted (584 files; declared deviation).

## Evidence

Coordinates: VA as shown by objdump; .text file offset = VA - 0x1000. FDE bounds from .eh_frame (PC-relative sdata4, fixed 4-byte range fields, CIE pointer relative to the CIE_id field, rec+4; FDE list sorted before bisect; own parse of 135,313 FDEs). Previous FDE 0x636b8f0..0x636b937 (gap 9 bytes, all 0xcc); next FDE 0x636bd90..0x636c49c (padding 0; this is packet #282's window, adjacent, not overlapping).

Raw disassembly: see the .objdump.txt exhibit (228 strict lines, 6 calls, 1 ret, 1 bsr, 0 lock sub, 1 lock add). Call targets: 0x6364880 (helper, 1x), 0x63d9880 bin_table_init (2x: 0x636baf8, 0x636bb5d), 0x63d9700 lu-miss (2x: 0x636bcee, 0x636bd81), 0x63f0d70 __stack_chk_fail (1x). No other call target. No branch target leaves the window (verified by program); the single exit is ret at 0x636ba87.

Key decode points: entry rdi = context (rbp), rsi = size (rdx); key = helper 0x6364880 return (rbx); table = context + 0x1b0; top index (key >> 0x1a) & 0xf0; high bits key & 0xffffffffc0000000; second level (key >> 0x9) & 0x1ffff8 + table + 0x8; node resolution via 0x6727a00[(value >> 0x30)]; field extraction shl/sar $0x10 + mask $0xffffffffffffff80; 0x65096c0 indexed by (value & 0xfff); lock add %r14,0x38(%r13) at 0x636ba57. Size gate: cmp $0x1000,%rdx, ja 0x636ba90; threshold byte from 0x67277c0[(rdx + 7) >> 3]; size-class block with bsr at 0x636bab9 and 0xe8 fallback at 0x636bbb8. Both bin_table_init sites pass lea 0x10(%rsp) (r12 at site 1, rdx at site 2, each block the target of exactly one je on a null-context test). Scans: 8 slots at table + 0x100, move-to-front on hit, reversed-operand compares at 0x140/0x150 (scan 1) and 0x120/0x130/0x140 (scan 2).

Analysis was complete for this window (all 228 strict lines read); no timeout, no range limit beyond the FDE bounds.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed in this packet; this is an evidence packet only (observation + verifier + tests). No Cargo build, no normalized comparison, no fixture identity is claimed.

## Results and limitations

Metrics with denominators: strict 228/228 lines accounted for in the census; calls 6/6 classified by rel32 target; bti sites 2/2 with branch/argument/rejoin verified; miss sites 2/2 with arguments/rejoin verified; ret 1/1 (site 0x636ba87); bsr 1/1 (site 0x636bab9); lock sub 0, lock add 1/1 (site 0x636ba57); gap 9/9 bytes int3; padding 0/0; disjointness NONE over prior ranges, 0 records skipped (verifier count at run time); raw-e8 total 108 with tiers 10x1, 8x1, 6x2, 5x1, 4x8, 2x12, 1x17; this FDE 2 raw sites.

What passed/failed: verifier exit 0, unit tests exit 0, make verify exit 0; make catalogue-check exit 2 is the pre-existing new-base failure, not a packet regression; full make test not attempted (declared deviation, not hidden).

What remains unknown: helper 0x6364880's internals (what the threshold/size-class rcx argument does inside it); runtime values of the .bss tables; the runtime purpose of the lock-add increment beyond its field pattern. Next question: build packet #291 on 0x63c89c0..0x63c8d5a (922B, 2 bti, 2 miss, 0 ret, 0 bsr), after re-verifying its site count and claim status; fall through the surviving 2-raw list in order if it fails.
