# RE-009 · Node #115 checkpoint nine-word comparison network

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [restore canonical-height packet](../RE-017-node115-restore-canonical-heights/README.md) links checkpoint enumeration to the shared numeric sorter but leaves the large-sort path open. The [prune small-sort packet](../RE-009-node115-checkpoint-prune-small-sort/README.md) proves the selected insertion path for lengths 2–8 and leaves the larger comparison networks unresolved. This packet examines one such network.

For the selected `0x14c6420` helper path, a current range length of 9–12 selects the straight-line network at `0x14c67df`–`0x14c6997`. It reads the first nine unsigned 64-bit words, applies unsigned compare and conditional moves, and writes nine words back; the following insertion/merge work for remaining words is outside this packet. On the selected mixed-input route, `0x15506d0` tail-jumps to this helper when its current range is at most 32. For helper inputs 21–25, the first half length is 10–12, so it selects this network, assuming the earlier caller reaches that route and buffers are valid. This does not establish the complete sort, arbitrary path reachability, successful checkpoint restore, or state-root equivalence.

The verifier authenticates the pinned binary and FDEs, checks call/branch targets and 123 contiguous network instruction spans against an independent local GNU objdump decoding, then interprets only the supported unsigned compare/move subset on synthetic words. It verifies all 512 binary inputs, plus high-bit and maximum-word examples. Because this is a fixed network of min/max comparisons, the binary-input check extends ordering and multiplicity to arbitrary unsigned words by thresholding; it is a static model of the decoded sequence, not execution of the captured target. An inverted conditional-move mutation must fail. No captured binary is executed.

## Reproduce

From the repository root with GNU objdump 2.45 and Python 3:

```sh
python3 research/work-items/RE-009-node115-checkpoint-nine-word-network/verify.py
```

GNU objdump 2.45 and LLVM objdump 23.1.4 agreed on the recorded spans. The synthetic verifier does not establish ABI behavior, memory safety for invalid inputs, or the correctness of later insertion or merge steps. Next: trace the remaining insertion and merge paths and independently compare their full outputs against target-grounded cases under separately authorized execution.
