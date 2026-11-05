# RE-001: map node115 listener timestamp conversion error and day record

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The observer refresh delegates timestamp-record creation to this wrapper. It rejects an upstream tag of two and fraction values at or above one billion, then passes the selected pair and a zero record to the difference helper. A tagged difference error is converted separately. The ordinary path rejects a seconds word with nonzero high 32 bits, then converts the remaining seconds to a day index and a remainder using the retained multiply/shift and 86400 scale.

The successful output has tag zero and three dwords. The error branches publish tag one and an error pointer. This maps the result record and arithmetic boundaries without invoking the host timestamp source.

The retained 1 full FDEs cover 273 bytes and 63 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 3 instruction/data windows, 2 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-listener-observer-timestamp-record-115/collect.py --out work/listener-observer-timestamp-record-fresh
python3 -B research/work-items/RE-001-listener-observer-timestamp-record-115/verify.py --out work/listener-observer-timestamp-record-check-fresh.json
```
