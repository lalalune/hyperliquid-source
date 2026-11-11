# RE-009 · Node #115 checkpoint thirteen-word comparison network

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [restore canonical-height packet](../RE-017-node115-restore-canonical-heights/README.md) links checkpoint enumeration to a shared numeric sorter but leaves large-sort behavior open. The [prune small-sort packet](../RE-009-node115-checkpoint-prune-small-sort/README.md) establishes the selected 2–8 insertion path. [#5920](https://github.com/lalalune/hyperliquid-source/pull/5920) checks a distinct nine-word network. This packet examines the different thirteen-word network.

For a valid current range of 13–16 unsigned 64-bit words in `0x14c6420`, the selected straight-line network at `0x14c649a`–`0x14c67b7` reads the first thirteen words, applies unsigned compare and conditional moves, and writes those thirteen words back in ascending order. It leaves later insertion and merging outside this packet. On the selected mixed-input route, `0x15506d0` tail-jumps to this helper when the current range is at most 32. For helper inputs 26–32, its first half is 13–16 words and therefore selects this thirteen-word network, subject to caller reachability and valid buffers. This does not establish the complete sorting path, checkpoint restore, or state-root equivalence.

The verifier authenticates the pinned binary and indexed FDEs, checks selected call/branch targets, and independently decodes 220 network instruction spans using local GNU objdump. A static interpreter supports only the unsigned compare/move operations in this network; it checks all 8,192 binary inputs, high-bit and maximum-word examples, and an inverted conditional-move control. Since this is a fixed min/max comparison network, the zero-one principle extends those binary checks to unsigned ordering and multiplicity for arbitrary words. The interpreter does not execute target bytes or prove later insertion/merge behavior.

## Reproduce

From the repository root with GNU objdump 2.45 and Python 3:

```sh
python3 research/work-items/RE-009-node115-checkpoint-thirteen-word-network/verify.py
```

GNU objdump 2.45 and LLVM objdump 23.1.4 agreed on the recorded spans. Next: trace remaining insertion and merge paths and independently compare complete outputs under separately authorized offline execution. No runtime reachability or memory safety claim follows from this static model.
