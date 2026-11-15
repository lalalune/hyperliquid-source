# Node #115 tracker: wrapped 80-byte threshold lookup

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Static conditional analysis; the separately submitted nonwrapped split path does not cover this branch.

`0x4de568a` calls `0x57f2890` with a flat 80-byte-record ring and threshold key. For a valid wrapped ring of capacity C, head H<C, count L with C-H < L <= C, let N=C-H and M=L-N. Its logical sequence is the N rows at H..C-1 followed by M rows at 0..M-1. The helper compares the first key in the second segment with the threshold using unsigned order (`0x57f28b7..0x57f28c1`). If that key is at least the threshold, it searches the first segment; otherwise it searches the second segment and adds N to the returned index (`0x57f2947..0x57f2989`). Both binary searches operate on qword keys with 80-byte strides.

If logical keys are nondecreasing, the result is the first logical index whose key is >= threshold, or L when all keys are smaller, including equality across the wrap boundary. This follows from the segment choice and each search's unsigned lower-bound comparison. Invalid metadata, concurrent changes, allocation and copying, later processing, and the protocol meaning of the keys remain unproven.

Run `python3 research/work-items/RE-017-node115-tracker-wrapped-threshold/verify.py` to authenticate the target, check both branch windows and the direct call, and reject anchor mutations. `windows.txt` records the selected disassembly; no target code is executed.
