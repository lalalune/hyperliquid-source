# RE-017: selected short-run scratch capacity across four boundaries

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This static packet connects the scratch wrapper from #6617 to the selected short-run branch in #6620 and checks the next callee's capacity guard. No captured code is executed.

## Bounded deduction

For an original selected caller count `n` between 21 and 64 inclusive, under normal returns and valid pointer/length inputs:

1. The `0x36e3320` scratch wrapper computes `max(ceil(n/2), min(n, 250000)) = n`. Since `n <= 64`, its `scratch_count <= 128` branch supplies a stack pointer and capacity `128` to `0x3df8160`, and sets the saved flag for `n < 65`. #6617 describes the wrapper's general scratch formula.
2. On the specific branch at `0x3df82b2` where a positive remaining count is smaller than the local threshold and the saved flag is nonzero, the helper passes `min(remaining, 32)` as its selected count to slot `0x64e98a0`, retaining the original scratch capacity in the `rcx` argument. The target ELF's relative relocation binds that slot to `0x42e26a0`. #6620 records the threshold and branch without analyzing this downstream path.
3. At `0x42e26bf`, a count below 33 takes the short dispatch to `0x43b34e0`; the selected call forwards the count and capacity. Thus this particular branch reaches the short helper with count at most 32 and capacity 128.
4. The short helper returns early for count below two. Otherwise it computes `count + 16` and branches to `0x43b3b83` if capacity is smaller. For the selected bounds, `count + 16 <= 48 < 128`, so this *one capacity guard* is not taken. This conclusion does not establish that any other guard, memory access, ordering result or allocation is safe.

The deduction is conditional on the selected control-flow path, valid inputs, static relocation binding, and normal calls; it does not prove runtime reachability, full sorting correctness, quorum, authentication or state-root equivalence. Unselected branches, the implementation of `0x43b34e0`, helper side effects and failure behavior remain open. No component gate is advanced.

## Reproduce

```sh
python3 research/work-items/RE-017-node115-short-run-scratch-bound/verify.py
readelf -rW artifacts/node/115/hl-node | rg '00000000064e98a0'
```

The packet retains four bounded Apple LLVM objdump windows and records addresses in linked ELF virtual coordinates. The verifier authenticates the target SHA-256, checks eleven selected byte anchors, two direct-call displacements and one indirect slot/relative relocation, and rejects eleven single-byte anchor mutations. It does not prove all register dataflow, full CFG, helper effects, input validity or runtime behavior. The capacity inequality is a mathematical inference from the selected observed instructions and the stated count bounds; it is not a whole-function test.
