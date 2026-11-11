# RE-012: map node115 resolver list projection and release

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The resolver consumer asks the iterator for its first
address record. Discriminator two frees the original list
and produces a zero-length result. An admitted record
starts an allocation of 128 bytes and initial capacity four.

Further iterator results append fixed 32-byte records. The
loop grows the storage only when length equals capacity
and stops at discriminator two. It frees the original
list before returning the allocated base, capacity and
end pointer computed with a 32-byte stride. The retained
unwind edges release the list and locally owned storage.
This scope follows result consumption, separate from lookup.

The retained 1 full FDEs cover 848 bytes and 199 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 2 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-resolved-address-vector-115/collect.py --out work/resolved-address-vector-fresh
python3 -B research/work-items/RE-012-resolved-address-vector-115/verify.py --out work/resolved-address-vector-check-fresh.json
```
