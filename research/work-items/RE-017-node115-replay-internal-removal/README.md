# RE-017: replay traversal nonzero-depth replacement (#115)

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses are ELF virtual addresses. This extends #6625's zero-depth compaction to the distinct nonzero-depth path of the traversal helper used by #5157 and #6624. The prior handoff packet retains this function as raw instructions but does not establish the replacement path.

## Observed path

For a descriptor `(node, depth, index)` with nonzero depth, `0x4d31c60` first loads the child at `node+0xe8+8*index`. It then follows `depth-1` links, each at `current+0xe8+8*count`, where count is the 16-bit field at `current+0xe6`. The loop is partially unrolled by eight. At the reached node it builds a zero-depth descriptor with index `count-1` and calls `0x4d2c060` (`0x4d31d75`). The latter's output contains the selected 8-byte field, 12-byte field, and a returned `(node, depth, index)` descriptor (`0x4d2c2a5..0x4d2c2ca`).

After the helper returns, `0x4d31d9f..0x4d31dc4` advances through parent pointers while the returned index is at least that node's count. At the first node for which the index is below count, `0x4d31dca..0x4d31df4` saves that node's selected 8-byte and 12-byte fields and replaces them with the values returned by the leaf helper. This is the predecessor-style replacement mechanism inferred from the indexed child and rightmost-child traversal; the exact semantic names and subsequent traversal/output handling are outside this packet.

The interpretation assumes a valid, finite tree, `depth>0`, valid child pointers, a nonempty reached leaf, a valid returned descriptor and normal helper return. Neither the raw instruction anchors nor that conditional reasoning establish runtime reachability or resolve the helper's balancing and exceptional paths. No checkpoint-height or state-root claim is made.

## Reproduction

Run `python3 research/work-items/RE-017-node115-replay-internal-removal/verify.py`. The verifier authenticates the target and checks six instruction anchors, the direct call and six one-byte mutation controls. `windows.txt` contains `/usr/bin/objdump -d --x86-asm-syntax=intel` excerpts. No captured code is executed, and no completion gate is changed.
