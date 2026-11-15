# RE-017: large candidate path scratch sizing

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This packet follows the selected count-at-least-21 indirect call left open by #6615. No captured code is executed.

## Static observations

- The call at `0x5348713` loads its destination from `0x64e4e18`. The target ELF contains an `R_X86_64_RELATIVE` entry for that slot with addend `0x36e3320`. This is static relocation interpretation, not a measurement of a running process pointer.
- In the selected FDE interval `0x36e3320..0x36e342a`, the incoming count `n` in `rsi` is used to compute `ceil(n / 2)` and `min(n, 250000)`; an unsigned comparison selects the larger of these values. The resulting word is called `scratch_count` here. This formula is an interpretation of the recorded arithmetic and conditional moves, not a source-level identifier.
- If `scratch_count <= 128`, the selected path supplies the function's 4,096-byte stack area and capacity 128. Otherwise it calculates `scratch_count * 32`, checks arithmetic-related conditions, and requests that many bytes through slot `0x64df480`. The packet does not establish the allocator's complete semantics or claim all possible inputs succeed.
- The body calls `0x3df8160` with the selected scratch pointer/capacity and a flag set when `n < 65`. After its normal return, the heap-backed path frees the scratch allocation when `scratch_count > 128`. Separate overflow, allocation-failure and unwind paths exist. No ordering, comparison, quorum or root behavior is attributed to `0x3df8160` here.

The selected caller has counts of at least 21; this packet does not claim all callers have that precondition or that all count values are reachable. The complete FDE disassembly is retained as a review aid, not proof of complete CFG, target equivalence or runtime execution. No component gate is advanced.

## Reproduce

```sh
python3 research/work-items/RE-017-node115-large-candidate-scratch/verify.py
readelf -wf artifacts/node/115/hl-node | rg 'pc=00000000036e3320'
readelf -rW artifacts/node/115/hl-node | rg '00000000064e4e18'
/usr/bin/objdump -d --x86-asm-syntax=intel --start-address=0x36e3320 --stop-address=0x36e342a artifacts/node/115/hl-node
```

The verifier authenticates the target SHA-256, checks nine selected instruction anchors, resolves one direct call and the caller's indirect slot and unique relative relocation, and rejects nine single-byte anchor mutations. FDE inspection is separate. These checks do not validate all machine instructions, helper effects, allocation failures or dynamic behavior. #6615 records the caller and explicitly leaves this indirect target open.
