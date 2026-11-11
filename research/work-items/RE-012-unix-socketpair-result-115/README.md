# RE-012: map node115 Unix socket pair ownership and result handoff

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The selected Unix socket pair helper ORs input type with 0x80800,
initializes both local descriptor slots to -1 and calls socketpair
with domain 1 and protocol 0. A negative result reads errno and
publishes dword tag 1 and the packed errno at +8. The nonnegative
path checks both descriptor sentinels before publishing dword tag
0 and the two descriptors at +4 and +8. Diagnostic and exceptional
close edges are retained in the same FDE.

The caller at 0x5cfced2 supplies type 1 and checks tag 1 before using
the descriptor words. Its success continuation preserves the pair
across the next two calls and uses PSHUFD immediate 0xe1 to reverse
the low two dwords in the outgoing qword. A separate exceptional
continuation closes the second preserved descriptor, then the first,
before unwind resume. This scope binds the pair transfer and
ownership edges. Downstream helper semantics and LSDA action
interpretation are outside it. Qualification reads captured bytes.

The retained 2 full FDEs cover 375 bytes and 96 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 9 instruction/data windows, 0 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-unix-socketpair-result-115/collect.py --out work/unix-socketpair-result-fresh
python3 -B research/work-items/RE-012-unix-socketpair-result-115/verify.py --out work/unix-socketpair-result-check-fresh.json
```
