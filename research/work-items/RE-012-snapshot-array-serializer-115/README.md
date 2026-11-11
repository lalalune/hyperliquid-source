# RE-012 snapshot array serializer entry

Target Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The mode-0 and mode-1 snapshot output workers both call 0x2529970. This packet resolves the shared callee's descriptor intake, empty framing and span rollover.

- The entry copies 72 bytes from RSI to its stack. If the first qword is 2, it takes differences of two endpoint pairs, shifts each right by five and multiplies by 0xaaaaaaaaaaaaaaab before adding the results. For well-formed nonnegative spans divisible by 96, this computes the combined element count using the multiplicative inverse of 3 modulo 2^64. For the other descriptor arm, it uses the qword at input +0x40.
- The writer depth word at +0x18 is checked against all ones before incrementing it. The normal arm clears the byte at +0x20, appends an opening bracket, and takes a capacity branch when length equals capacity. For a computed count of zero it restores the old depth and appends the closing bracket, with a separate capacity branch.
- At 0x2529a70 the tag-2 iterator checks the first start/end pair for equality. If exhausted, it swaps the two span records and tests the new active pair. The selected item path advances the active pointer by 96 and derives an address at item +24. The per-item schema and remaining writer state transitions are open.

One full FDE contains 497 instructions and 1,963 bytes. GNU, LLVM and Capstone agree on the instruction partition. GNU readelf independently confirms the extent. The verifier rejected five modified instruction windows, one changed memcpy import relocation and two altered target identities. The target was examined statically. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

Run from the repository root with authenticated inputs and the versions in tools.json. Use fresh output paths.

```sh
python3 -B research/work-items/RE-012-snapshot-array-serializer-115/collect.py --out work/snapshot-array-fresh
python3 -B research/work-items/RE-012-snapshot-array-serializer-115/verify.py --out work/snapshot-array-check-fresh.json
```
