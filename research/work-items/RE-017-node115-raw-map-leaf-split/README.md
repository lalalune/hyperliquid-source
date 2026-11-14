# Node #115 raw-map full leaf split

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The containing FDE is `0x4c3f280..0x4c3fde6`; this is conditional static analysis, not execution.

For a valid full node with 11 entries and insertion index i in 0..11, `0x4c3f2c8..0x4c3f3ca` selects an existing pivot slot p and insertion side: p=4 and left for i<5; p=5 and left for i=5; p=5 and right for i=6; p=6 and right for i>=7. The selected new-side index is i on the left, zero for i=6, and i-7 for i>=7. This is an index mapping, not a proof of sortedness or duplicate handling.

After successful allocation of 0xe8 bytes, `0x4c3f400..0x4c3f49e` saves the old pivot key and 12-byte value, requests copies of `11-p-1` trailing key/value slots to the new node, sets the old node's count to p and the new node's count to `11-p-1`. `0x4c3f4b9..0x4c3f569` selects the side, makes space as needed, inserts the new key and 12-byte value, and increments that side's count. On these paths, the old pivot is kept separately for subsequent processing; the copy calls use slot `0x64df508`, whose ELF relocation names `memcpy@GLIBC_2.14`. The subsequent overlapping shifts use slot `0x64df568`, relocated to `memmove@GLIBC_2.2.5`. These are pinned import names, not runtime binding observations; parent propagation remains outside the finding. Allocation failures, corrupt metadata, and live reachability are not established.

Run `python3 research/work-items/RE-017-node115-raw-map-leaf-split/verify.py` to authenticate the target and check anchored bytes with mutation controls. `windows.txt` provides the disassembly; no target code is executed.
