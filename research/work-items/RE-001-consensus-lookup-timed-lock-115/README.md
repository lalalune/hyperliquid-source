# RE-001: map node115 consensus lookup timing and lock handoff

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The listener lookup dispatches to this alternate helper on the selected zero-flag route. The alternate helper samples the clock before trying the lock at object +0x6a8 and again after acquisition. The fast path adds 16 using locked compare-exchange. The bit-three check, upper word bound, or failed exchange dispatches to the bound slow helper. The two samples are handed to the known difference helper in second-sample then first-sample order.

A selected normal result releases by subtracting 16 with locked xadd. It calls the bound wake helper only when the masked old word equals 0x12. Two exception landing routes use the same subtraction and wake predicate before resuming. This packet maps the timing interval and release behavior without interpreting the alternate helper lookup result.

The retained 1 full FDEs cover 1736 bytes and 383 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 2 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-consensus-lookup-timed-lock-115/collect.py --out work/consensus-lookup-timed-lock-fresh
python3 -B research/work-items/RE-001-consensus-lookup-timed-lock-115/verify.py --out work/consensus-lookup-timed-lock-check-fresh.json
```
