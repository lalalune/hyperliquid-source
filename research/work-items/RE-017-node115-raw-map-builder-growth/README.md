# Node #115 raw-map tree builder full-node growth

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This is conditional static evidence for the separately identified sorted-record builder.

After obtaining a nonzero-marked record, `0x4cc2a69..0x4cc2a75` checks the current node's 16-bit count against 11. On a full node, `0x4cc2a80..0x4cc2a96` walks the pointer at offset 0 while encountered parent counts are at least 11. If the walk reaches a null parent, `0x4cc2aa0..0x4cc2af0` requests 0x148 bytes, initializes the new node's parent pointer and count to zero, links the prior root at +0xe8, links the prior root back to the new node, and increments the stored height. Allocation and integer overflow failure branches remain open.

At the selected nonfull ancestor `0x4cc2af4..0x4cc2b70` requests a 0xe8-byte node and, when the tracked level count exceeds one, builds a chain of 0x148-byte nodes. Then `0x4cc2b70..0x4cc2bba` checks the ancestor count is below 11, stores the pending key and its first 12 value bytes at count-indexed slots, places the newly created child at +0xf0+8*count, increments the count, and sets the child's parent and parent-slot index. This describes visible links only; the full builder's ordering, failure cleanup, and runtime equivalence are not claimed.

Run `python3 research/work-items/RE-017-node115-raw-map-builder-growth/verify.py` to authenticate the target, compare instruction anchors and reject mutations without executing it. Disassembly is in `windows.txt`.
