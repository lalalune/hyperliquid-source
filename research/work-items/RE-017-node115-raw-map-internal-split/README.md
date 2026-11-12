# Node #115 raw-map insertion: full internal-node split

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Static bounded analysis of FDE `0x4c3f280..0x4c3fde6`; no target execution.

When split propagation reaches a full parent, `0x4c3f5da..0x4c3f602` reads its 16-bit child index j and count. For the valid case count=11 and j in 0..11, `0x4c3f602..0x4c3f647` selects pivot p=4 for j<5, p=5 for j=5 or 6, and p=6 for j>=7. It selects the old side for j<=5 and the new side for j>=6, remapping the new-side insertion index to 0 when j=6 and j-7 when j>=7.

After successful allocation of 0x148 bytes, `0x4c3f685..0x4c3f722` saves pivot key and 12-byte value, sets right count to `11-p-1`, requests copies of that many trailing key and value slots, and sets left count to p. It then checks that the number of child pointers to copy equals right count+1 and requests the copy from old child slot p+1 to new child slot 0 (`0x4c3f744..0x4c3f780`). The immediately following loop begins updating copied children's parent links and indices.

This finding bounds the pivot and copy requests, not the indirect memory-copy implementation, full propagation to the root, allocation/error behavior, or real checkpoint execution. The separately traced nonfull parent and root-promotion paths are distinct continuations.

Run `python3 research/work-items/RE-017-node115-raw-map-internal-split/verify.py` to authenticate the target and check instruction anchors and mutations; `windows.txt` contains the disassembly.
