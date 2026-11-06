# RE-012 snapshot book pair value writer

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The book_orders field writer in PR #3573 calls 0x229aa10. This packet establishes the value's framing and the order of its child calls. The entry checks the depth word at +0x18 against all ones. The normal arm increments depth, clears +0x20, appends an opening bracket and a line feed, then repeats the configured indentation span at the incremented depth. A zero indentation length bypasses copying. For a nonzero span, insufficient capacity calls the growth helper, then the loop copies bytes through the memcpy import and advances the output length.

The first child call at 0x229aaf7 goes to 0x2538070. Nonzero return exits before the next child. On success the writer sets +0x20 to 1. The second child call at 0x229abc4 targets the same helper. Its status is checked before the finalizer at 0x2331920. Child record semantics remain open.

The full FDE spans 628 bytes and 163 instructions. GNU, LLVM and Capstone agree on instruction partitions, and GNU readelf confirms the extent. Replay rejected four window mutations, one import mutation and two identity controls. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-book-pair-value-115/collect.py --out work/snapshot-book-pair-fresh
python3 -B research/work-items/RE-012-snapshot-book-pair-value-115/verify.py --out work/snapshot-book-pair-check-fresh.json
```
