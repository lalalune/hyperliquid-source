# RE-017: selected large-candidate run thresholds

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This packet follows `0x3df8160`, the helper called with scratch storage in open #6617. It does not execute captured code.

## Selected static observations

- The direct call at `0x36e33bd` enters `0x3df8160`; the selected caller sets its `r8b` flag for `n < 65`. The callee saves the count and flag, and branches to its epilogue when `n < 2`.
- For `2 <= n <= 4096`, the qword placed at local stack `+0x20` is `min(ceil(n / 2), 64)`. For `n >= 4097`, the selected instructions compute `m = floor(log2(n | 1))`, `k = ceil(m / 2)`, and `(2^k + (n >> k)) >> 1`, using machine-width arithmetic. These are interpretations of the arithmetic/conditional moves, not proof of a source-level name or a complete algorithm.
- The processing loop compares a remaining count against this qword. When the remaining count is smaller and the saved flag is nonzero, it selects at most 32 and calls through `0x64e98a0`. The selected call uses a 32-byte stride elsewhere in the loop. When the remaining count is smaller and the saved flag is zero, a different branch is taken. Neither branch is claimed to produce a particular ordering without analyzing the other helper effects.
- The target ELF has a relative relocation from `0x64e98a0` to `0x42e26a0`; this is a static binding, not a runtime pointer measurement. The target helper body, comparison and merge semantics, other callers, allocation behavior and full candidate correctness remain outside scope.
- `readelf -wf` records FDE interval `0x3df8160..0x3df87f3`; the disassembly is retained for review. An FDE is not proof of all function boundaries, full control flow or runtime reachability. No component gate is advanced.

## Reproduce

```sh
python3 research/work-items/RE-017-node115-large-candidate-runs/verify.py
readelf -wf artifacts/node/115/hl-node | rg 'pc=0000000003df8160'
readelf -rW artifacts/node/115/hl-node | rg '00000000064e98a0'
/usr/bin/objdump -d --x86-asm-syntax=intel --start-address=0x3df8160 --stop-address=0x3df87f3 artifacts/node/115/hl-node
```

The verifier authenticates the target SHA-256, checks eleven selected instruction anchors, resolves one direct call and one indirect slot/relative relocation, and rejects eleven single-byte anchor mutations. It does not prove full CFG coverage, all arithmetic domains, helper behavior or dynamic equivalence. #6617 documents the caller's scratch selection; this packet analyzes the selected callee's initial threshold and branch, not the full large-count algorithm.
