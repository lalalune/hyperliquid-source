# Node #115: 24-byte raw-map short-sort bidirectional merge

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This traces the previously excluded final merge of the 24-byte short-sort helper `0x5414750`, distinct from the 20-byte tracker-key comparator.

Scratch holds two sorted halves split at floor(n/2). At `0x5414b60..0x5414bb2` the loop compares their first qwords as unsigned keys. In a tie the left front is copied to the forward output and the right back is copied to the backward output. It copies complete 24-byte records as a 16-byte and an 8-byte part, and updates the selected front and back pointers. For valid sorted, disjoint scratch halves this tie selection preserves left-before-right ordering within the observed merge.

The loop performs floor(n/2) iterations. For odd n `0x5414bed..0x5414c1d` selects and copies the remaining middle record based on the remaining interval. `0x5414bc4..0x5414c37` checks that both intervals are exhausted before returning; otherwise control reaches the failure slot `0x64dfb58`. Failure behavior, other sort branches and full-sort equivalence are outside this observation.

Run `python3 research/work-items/RE-017-node115-raw-map-short-merge/verify.py` for digest, anchor and mutation checks without execution. The static disassembly is recorded in `windows.txt`.
