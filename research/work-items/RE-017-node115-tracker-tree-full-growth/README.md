# Node #115: full right-edge tracker-key tree growth

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This follows the full-node branch of the selected 20-byte key deduplication builder, previously bounded to nonfull leaf insertion.

At `0x4ca99ef..0x4ca9a26`, a node with at least 11 keys causes a parent walk through offset `+0`, counting full ancestors until a node with fewer than 11 keys or a null parent is found. When the walk reaches null, the code allocates 0x148 bytes, initializes a zero-count root, links its child zero to the previous root and updates the old root's parent and child index; it then updates the tree root and increments the stored height, with a separate overflow branch.

On the successful allocation path, `0x4ca9a86..0x4ca9b00` creates a 0xe8-byte leaf and, for each remaining level, wraps it in a 0x148-byte internal node with zero count and child-zero/parent links. At `0x4ca9b02..0x4ca9b48` the saved 20-byte key is appended to the available ancestor at stride 20, the new subtree is installed in child slot count+1, and its parent/index fields are set. The descent at `0x4ca9b5a..0x4ca9c1f` follows rightmost child indices back to the new leaf before incrementing the external count.

This is the selected successful full-right-edge growth path, assuming valid tree invariants and successful allocation. Allocation failure/unwind paths, general insertion and protocol meaning remain open. Run `python3 research/work-items/RE-017-node115-tracker-tree-full-growth/verify.py` to check the pinned digest, anchors and mutation controls without target execution. `windows.txt` contains disassembly and allocator relocation.
