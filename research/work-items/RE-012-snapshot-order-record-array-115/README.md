# RE-012 snapshot order-record array writer

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The paired-field writer calls 0x2538070 for untriggered_orders. The book pair writer also calls this helper for both values. This packet follows the shared array writer beneath those call sites.

The entry guards the depth word against all ones and emits the opening bracket. A zero element count branches around the per-element loop. The loop gates copying of the indentation span on both the repetition count and a nonzero span length. The observed copy goes through the memcpy import and advances the writer length. A capacity failure calls the growth helper before retrying the copy.

At 0x25381df, the writer dispatches the current element to 0x22b8e00. A nonzero result branches to the error return before advancement. The success route advances the element pointer by 208 bytes, sets the writer state byte to 1 and compares the pointer against the previously computed end. The normal closing path emits a closing bracket. The element schema and source-level names remain open.

The retained GNU, LLVM and Capstone instruction partitions agree across the full 824-byte FDE. GNU readelf confirms its extent. Replay rejects four window changes, one import mutation and two identity controls. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-order-record-array-115/collect.py --out work/snapshot-order-array-fresh
python3 -B research/work-items/RE-012-snapshot-order-record-array-115/verify.py --out work/snapshot-order-array-check-fresh.json
```
