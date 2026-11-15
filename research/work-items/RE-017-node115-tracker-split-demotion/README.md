# Node #115 tracker tree split: representation demotion thresholds

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This is static, conditional evidence on the sentinel tree-split path.

After the independently traced tree split and count partition, `0x4de5651..0x4de5679` preserves the new-side count in r13, stores the old-side count into the original header, and tests whether the original representation still has the sentinel. On the selected sentinel continuation, `0x4de5751` compares the old-side count with 31. Counts 0..31 enter the builder at `0x4de57da`; counts >=32 bypass that conversion. The selected branch stages a descriptor from the original root, height and count, then stores the builder's returned buffer/capacity and count back in the header with head zero (`0x4de584d..0x4de5860`).

Independently, `0x4de5864..0x4de58ed` checks the new-side count against 31 and invokes the same builder for counts 0..31; >=32 bypasses that conversion. At `0x5b8e9c4..0x5b8ea17`, the builder reads its descriptor's count, checks the size bound and requests 80 bytes per entry, with a distinguished zero-count result. Thus the two sides are checked separately, and the observable boundary is 31/32 on this path. This does not prove allocation success, element ordering, transition reachability, or other representations.

Run `python3 research/work-items/RE-017-node115-tracker-split-demotion/verify.py` to authenticate the target and validate byte/direct-call anchors with mutation controls. Disassembly is in `windows.txt`; no target code is executed.
