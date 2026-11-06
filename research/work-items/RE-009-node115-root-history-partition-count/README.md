# RE-009 · Tree history partition counts

Target Linux x86-64 Node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Both history cutoff wrappers call 0x4ca3a30 after their tree partition boundary, at 0x4de4ad7 and 0x4de5b42. The first input is the original total, the second points to the retained descriptor, and the third points to the newly split descriptor.

The helper compares the two height words at descriptor +8. It walks the retained tree if its height is smaller. For equal heights or a smaller split tree it walks the split tree. Both selected walks start with the root key count at +0x1c2. They descend through the leftmost child first, adding each visited node's count once. After a descent they try the next sibling slot, climbing through parent pointers at +0x160 and using the child's slot word at +0x1c0 until a next edge exists or the root is exhausted. A height of zero reads only the root count. The counted side is returned directly and the other side is computed by subtraction from the original total.

In both wrappers, RAX becomes retained descriptor +24 and RDX is carried into the split descriptor's count field. These observations establish the count handoff under valid tree metadata and an accurate original total. The choice compares heights and does not prove the walked side always has fewer keys. Tree balancing and any later conversion to a flat descriptor are outside this packet.

Run `python3 research/work-items/RE-009-node115-root-history-partition-count/verify.py` from the repository root. It checks the target extent, caller transfers and selected operands. A synthetic model compares the iterative walk and returned pair to a recursive oracle for 3,600 pairs of trees with varied heights and fan-out.
