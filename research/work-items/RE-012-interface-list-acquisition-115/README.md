# RE-012: map node115 interface list acquisition and interrupt retry

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The wrapper clears the list slot and calls getifaddrs.
Negative status captures errno and packs it before invoking
the local helper. Only errno four retries, reusing the same
list slot. A nonnegative status is accepted only when it
is zero and the returned list pointer is nonnull.

Success writes the same pointer at +8/+16 with the high-bit
marker at +0. Other outcomes allocate and copy the fixed
27-byte diagnostic, returning pointer and repeated length.
The packet covers acquisition and result ownership. It
does not enumerate interfaces or use the live host list.

The retained 1 full FDEs cover 228 bytes and 62 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 2 RELATIVE addends, 2 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-interface-list-acquisition-115/collect.py --out work/interface-list-acquisition-fresh
python3 -B research/work-items/RE-012-interface-list-acquisition-115/verify.py --out work/interface-list-acquisition-check-fresh.json
```
