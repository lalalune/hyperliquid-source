# RE-001: map node115 gossip snapshot span transfer and committed fields

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The ordinary gossip snapshot copy invokes this transfer helper for normalized spans. The source is traversed as 24-byte records, first using the cursor and endpoint in the first two words, then using a separate cursor and endpoint pair. Each transfer advances the selected source cursor, decrements the external remaining counter, and commits a dword, qword and byte to offsets zero, eight and sixteen of the destination entry. The destination count is incremented after those stores.

The second-span loop preserves the destination offset accumulated by the first span. Boundary exits distinguish remaining input from exhausted span state. The packet maps the three field stores and cursor updates, without claiming padding contents or a generic iterator ABI.

The retained 1 full FDEs cover 305 bytes and 86 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 3 instruction/data windows, 0 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-snapshot-span-transfer-115/collect.py --out work/gossip-snapshot-span-transfer-fresh
python3 -B research/work-items/RE-001-gossip-snapshot-span-transfer-115/verify.py --out work/gossip-snapshot-span-transfer-check-fresh.json
```
