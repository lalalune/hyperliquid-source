# RE-001: map node115 reserve layout overflow and allocator dispatch

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The shared reserve helper invokes this allocator adapter with new capacity, element width and alignment. It multiplies capacity by element width and rejects overflow or a size beyond the observed alignment-adjusted bound. Old capacity zero chooses the fresh allocation route, with a separate zero-byte result. Nonzero old capacity instead chooses the reallocation route. The alignment and allocation size choose different bound slots within both routes.

The return record distinguishes checked-layout failure, allocator null and success. Success publishes pointer and requested bytes; the error routes carry the selected error payload fields. The packet maps the dispatch and result contract without executing an allocator.

The retained 1 full FDEs cover 233 bytes and 74 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 3 instruction/data windows, 4 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-report-reserve-allocation-dispatch-115/collect.py --out work/gossip-report-reserve-allocation-dispatch-fresh
python3 -B research/work-items/RE-001-gossip-report-reserve-allocation-dispatch-115/verify.py --out work/gossip-report-reserve-allocation-dispatch-check-fresh.json
```
