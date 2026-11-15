# Node #115: selected stable merge of 20-byte tracker keys

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This follows the 20-byte tracker-key run discovery and reversal paths, rather than the separate 24-byte raw-map sorter.

At `0x3e4afc1..0x3e4b01d`, the selected merge requires a nonempty left run and scratch capacity of at least the smaller run length. It copies 20 times that smaller length to scratch through slot `0x64df508`, identified in the pinned ELF relocation as `memcpy@GLIBC_2.14`: the right run is copied when left is longer, otherwise the left.

In the longer-left branch, `0x3e4b030..0x3e4b08f` compares the last scratch-right entry against the last left entry using the `memcmp` slot `0x64dfb50`. A nonnegative result selects the right entry for the later output slot, including equal entries. In the other branch, `0x3e4b0a0..0x3e4b0f4` compares the front right entry against the scratch-left entry; a nonnegative result selects the left entry for the earlier output slot, including equal entries. Each selected entry is copied in 16-byte and 4-byte pieces.

Under valid adjacent sorted runs, disjoint scratch storage, and ordinary named-import behavior, these tie choices preserve left-before-right ordering in the observed loops. This does not prove the complete sorter stable: other merge paths, cleanup behavior, runtime bindings and reachability remain outside this window. The separate 24-byte merge is not evidence for this 20-byte specialization.

Run `python3 research/work-items/RE-017-node115-tracker-key-stable-merge/verify.py` for digest, instruction anchors and mutation controls without target execution. Disassembly and relocations are in `windows.txt`.
