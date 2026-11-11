# RE-012: map node115 alternate signal stack disable and unmap

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

A null supplied stack pointer skips the disable/unmap sequence.
For nonnull input, the routine recomputes usable size as
max(unsigned getauxval(0x33),0x2000) and loads the page size.

It constructs a stack record with null pointer, flags two and
the recomputed usable size, then calls sigaltstack with null
old-stack output. It subtracts page size from the supplied
usable pointer and adds page size to the usable length before
munmap. Neither return value is tested in this sequence. This
packet covers removal only. Existing evidence covers the
separate installation path.

The retained 1 full FDEs cover 1353 bytes and 285 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 3 instruction/data windows, 0 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-alternate-stack-unmap-115/collect.py --out work/alternate-stack-unmap-fresh
python3 -B research/work-items/RE-012-alternate-stack-unmap-115/verify.py --out work/alternate-stack-unmap-check-fresh.json
```
