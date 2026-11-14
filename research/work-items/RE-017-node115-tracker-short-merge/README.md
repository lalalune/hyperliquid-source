# Node #115: 20-byte short-sort bidirectional merge

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This follows the previously excluded final merge of short-sort helper `0x43893e0`, reached by the tracker-key sort.

The scratch array has two sorted halves, split at floor(n/2). At `0x43899b2..0x4389a19` each iteration compares the right-half front with the left-half front via 20-byte `memcmp`, copying the left on equality to the forward output. It also compares the right-half back against the left-half back, copying the right on equality to the backward output. Both copies retain the 16-byte and 4-byte parts; pointer updates advance only the selected front and retreat only the selected back. Under valid, separately allocated sorted halves and normal import behavior, these choices keep equal entries from the left half before those from the right half in the selected two-ended merge.

The loop runs floor(n/2) iterations. For odd n `0x4389a58..0x4389a86` selects the remaining middle entry according to which front/back interval remains. The subsequent checks require both halves exhausted before return; otherwise the code calls slot `0x64dfb58`. Failure-helper behavior, other sorter paths, runtime binding and full-sort equivalence remain open.

Run `python3 research/work-items/RE-017-node115-tracker-short-merge/verify.py` for target digest, instruction anchors and mutation controls without executing the captured binary. `windows.txt` includes the disassembly and comparator relocation.
