# RE-001: map node115 report error box construction and unwind ownership

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

Two report error handoffs return through different bound constructors. The first creates a local record with leading tag one and the incoming error word, and clears two trailing words. The second instead copies a three-word incoming record and appends two separate inputs. Both allocate 40 bytes and transfer five words only after a non-null return.

Both null paths pass the same size and alignment arguments to the error helper. Their unwind landing pads pass the respective local record to the shared drop helper before resuming. The packet identifies the distinct input layouts and common ownership contract without assigning unproven source type names.

The retained 2 full FDEs cover 241 bytes and 60 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 1 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-report-error-box-construction-115/collect.py --out work/gossip-report-error-box-construction-fresh
python3 -B research/work-items/RE-001-gossip-report-error-box-construction-115/verify.py --out work/gossip-report-error-box-construction-check-fresh.json
```
