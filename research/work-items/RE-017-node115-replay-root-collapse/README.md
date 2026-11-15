# RE-017: selected replay tree root collapse (#115)

## Question and scope

After low-count leaf repair (#6629), what does the caller do when its parent-repair helper reports an empty root? Target Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual-address coordinates. Main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`. The helper occupies FDE `[0x4c35400,0x4c35928)`; only selected entry and return windows are analyzed, not its entire balancing algorithm.

## Observations

`0x4d2c241` loads the repaired node's parent. A null parent skips the helper; otherwise it calls `0x4c35400` with that parent and the incremented traversal depth. If the returned low byte is nonzero, it also skips the following root adjustment (`0x4d2c24f..0x4d2c256`). In the helper's selected root case, a node with null parent returns zero precisely when its 16-bit count is zero; with nonzero count it returns one (`0x4c3544b..0x4c35464`, `0x4c3589c..0x4c358a7`). A count above four also returns one directly at entry. Other internal repair paths are not reconstructed here.

When the helper returns zero, the caller temporarily clears the incoming pointer slot. A null descriptor or zero descriptor depth branches to distinct exceptional calls. Otherwise it loads the descriptor's root pointer, replaces it with the qword at old root `+0xe8`, decrements descriptor depth, writes zero to the new root's first qword, calls indirect slot `0x64df4a0` with old root and size `0x148`, and restores the descriptor pointer (`0x4d2c258..0x4d2c2a2`). This supports a root-height collapse interpretation. It assumes valid descriptors and nodes, a nonnull new root, no alias interference, and normal indirect-call return; no runtime reachability, allocator semantics, complete balancing, checkpoint or state-root equivalence is claimed.

## Reproduction

From the root, `python3 research/work-items/RE-017-node115-replay-root-collapse/verify.py` authenticates the artifact and checks six instruction anchors, one direct target, and six independent one-byte mutation controls. `caller.txt` and `guard.txt` use Apple LLVM objdump 21.0.0 with `-d --x86-asm-syntax=intel`; `relocation.txt` contains the `readelf -rW` record. Python 3.11.15 was used. Static checks do not execute the target and no completion gate changes.
