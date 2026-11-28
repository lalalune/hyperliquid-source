# RE-017 · Node #115 replay worker initial Block append

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Analysis base `6d9382f821930b10d181cb90fe4a32756fd8e069`. The addresses are linked ELF virtual addresses.

## Question

The [outer wait-loop packet](../RE-001-node115-nv-stream-execution-wait-loop/README.md) starts after the initial helper has produced a retained descriptor. What actually happens to the Block and attachment pair on the worker's first poll, and how does a normal append either keep the buffer at its source or pass it to that wait loop? The [attachment handoff](https://github.com/lalalune/hyperliquid-source/pull/7273) supplies the two owners reaching the same worker.

## Observations

At `0x5a897e0`, worker descriptor W carries the replay future F at +0, Block owner A at +8 and attachment owner B at +0x10. The state byte at W+0x220 selects `0x5a8981b` for state zero. That entry loads the three qwords and passes them to the initial helper reached through slot `0x64ebfd0`, whose relative relocation is `0x5a89540`. The helper computes its selected incoming parent round and local receive baseline before the normal append branches. Its comparison at `0x5a895e3` requires equality on both routes below.

| Selected normal path | Append and resulting buffer ownership |
| --- | --- |
| A+0x188 equals the signed-minimum qword, existing count at most 99, append with capacity available | `0x5a89731/+0x5a8973a` writes A and B in order at the current F vector pointer plus `16 * count`. `0x5a89742` updates F+0x10 to count plus one. The helper returns byte `0x44` and places the signed-minimum qword at output+8. The outer worker follows its immediate-completion edge on that first descriptor word. |
| A+0x188 differs from the signed-minimum qword, moved buffer has append capacity | `0x5a8968c..0x5a896ac` saves the source vector words and resets F+0/+8/+0x10 to `(0,8,0)`. `0x5a896e6/+0x5a896ea` appends A and B to the saved storage using the same stride, updating the moved count. The helper returns byte `0x44` and four qwords at output+8: first vector word, row pointer, count including the new row, and the value loaded from A+0x340. The outer worker copies those words and reaches its initial wait-descriptor setup when the first word differs from the signed-minimum sentinel. |

The two routes store the same ordered pair but update different owners. An offline fixture should preserve this distinction, including the reset of the source vector before the moved append. Source-level meanings for A's +0x188 and +0x340 fields remain open. The capacity helper, other append paths, execution admission, runtime scheduling, and state-root effects are outside this packet. Both selected routes assume valid initialized owners and storage, normal returns, and no conflicting aliases.

## Reproduction

```sh
python3 -B research/work-items/RE-017-node115-replay-worker-first-append/verify.py
```

The [instruction spans](windows.txt) and [offline output](offline-log.txt) record the digest, indexed FDEs and independent GNU/LLVM comparison. The verifier checks the state-zero table entry, ABI and relocation, equality condition, native pair stores, descriptor words, and the first-word dispatch in the consumer. Synthetic controls cover retained and moved ownership with distinct pairs and validate that an altered byte cannot satisfy the instruction witness. The target is read as ELF data.
