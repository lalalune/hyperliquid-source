# RE-009 · Tree history cutoff redistribution

Target Linux x86-64 Node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Both selected history cutoff wrappers call the tree helper 0x4ca3ca0 on their sentinel representation arms, at 0x4de4ab7 and 0x4de5b22. This contribution follows the successful tree partition path and its node writes.

The helper allocates a 0x1c8-byte empty leaf. For each level in the old descriptor height it allocates a 0x228-byte parent, places the previously allocated child in slot zero, and records that parent and slot in the child. During partition, the old node's keys are compared as unsigned words at +0x168. The selected index is the first key at least as large as the cutoff, or the old key count if no such key occurs. The old count becomes the index. The paired new node receives the remaining count and copies that many eight-byte keys and 32-byte values from the old suffix.

At an internal level the new node's slot zero already leads down the parallel cutoff branch. The helper copies the old child links strictly after the cutoff edge into new slots beginning at one, one link per moved key. The selected grouped loop and scalar tail update each copied child's parent pointer at +0x160 and its new slot at +0x1c0. It then descends along the old cutoff edge and the paired new slot zero. This differs from redistributing a full node around an insertion pivot. The split is driven by the supplied cutoff and retains equal keys in the copied suffix.

After the split, one selected normalization loop replaces an empty internal root with its slot-zero child, decrements the recorded height, clears that child's parent pointer and releases the old 0x228-byte root. This evidence assumes valid input nodes, disjoint copy regions, successful allocations and ordinary helper returns. It leaves the complete rebalancing, unwind and final size-accounting paths open.

Run `python3 research/work-items/RE-009-node115-root-history-tree-cutoff/verify.py` from the repository root. The verifier checks the authenticated ELF extent, selected transfers and operands and models the cut and child slots for 156 synthetic node partitions.
