# Node #115 raw-map contiguous lookup

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Static analysis only.

`0x4dbe379` calls `0x57f95d0` with the non-sentinel raw map and a pointer to the sought 64-bit key. It tests the returned `rax`, and for nonzero `rax` and map count at least 64 takes its rebuild branch.

For a valid flat ring with capacity N, head H < N, count C <= N-H, and strictly increasing unsigned 64-bit keys, the lookup builds the contiguous slice at base + 24*H (`0x57f9675..0x57f9687`). Empty input returns `(rax, rdx) = (1, 0)`. For nonempty input, the loop `0x57f9694..0x57f96bf` compares the sought key to 24-byte-spaced entries. Its final comparison returns `rax=0` and the matching slice index in `rdx`, or `rax=1` and the insertion position in `rdx` if absent. Comparisons are unsigned. This explains the caller's zero/nonzero test on this bounded representation.

The wrapped-ring branches, invalid metadata, concurrent mutation, and duplicate-key ordering are not covered by this claim; no production reachability or live state is asserted.

Reproduce with `python3 research/work-items/RE-017-node115-raw-map-contiguous-search/verify.py`: it checks the exact target digest, byte anchors and call displacement, and rejects anchor mutations without executing the target. `windows.txt` contains the disassembly.
