# RE-012: node 115 gossip tree leaf iterator and collection

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. #5108 bounds one zero-height tree range and its two cursors. #5086 records the collector but leaves the tree iterator opaque; #5087 covers the separate ring-row iterator. #2402 examines a different, generic tree iterator and is not this call boundary.

## Selected path

Assume the non-empty flag-zero, zero-height, strictly ordered leaf range established by #5108, no mutation, valid node storage, and normal non-overflowing execution. Its result is passed as the iterator object: tag 2, current node and end node equal, depth zero, and indices `lo < hi <= key_count`. For every index `i` from `lo` through `hi-1`, `0x4e18c50` returns `rax = node + 0xb8 + 8*i`, `rdx = node + 16*i`, and advances the current index to `i+1`. When current node and index equal the end node and index, it returns `rax = 0`. The first address points to the qword used for ordered comparisons in #5108; the second addresses a 16-byte per-key region. We do not assign a source-level type to it.

On the selected success path, `0x5acca00` tests the returned `rax`, loads the two qwords from `[rdx]` and `[rdx+8]`, increments the qwords addressed by each loaded value with `lock inc`, and places those two loaded values, in order, into its 16-byte collection element. The normal-success assumption includes valid nonzero references and successful increments/allocation. In particular, it collects the two values **inside** the per-key region, not the address of the key or region. The result follows the selected producer and consumer boundaries only; allocator, growth, failure cleanup, lifetimes, live reachability, multi-level tree traversal, and ring mode are outside this packet.

## Static verification

`PYTHONPATH=tools python research/work-items/RE-012-node115-gossip-tree-leaf-iterator/verify.py` authenticates the target, iterator and collector unwind-described bodies, selected instruction bytes, direct calls and corruption controls. Synthetic index/range arithmetic checks do not execute or emulate the target. The proof composes with #5108's separate range preconditions rather than treating them as established for arbitrary iterator inputs.
