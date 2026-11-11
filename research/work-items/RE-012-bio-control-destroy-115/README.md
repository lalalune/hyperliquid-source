# RE-012: map node115 BIO control dispatch and destruction

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The control callback reads BIO data and dispatches on
command. Command 0x28 reads the qword at state +0x40.
Command 0xb returns one when state +0x20 is present;
its null branch takes a diagnostic. The ordinary default
returns zero.

The paired destroy callback returns zero for null BIO.
For nonnull BIO with state it drops that state and releases
the 0x48-byte allocation, then clears BIO data and init
and returns one. A nonnull BIO with absent data takes a
diagnostic. This scope concerns control and destruction,
separate from setup and data transfer.

The retained 2 full FDEs cover 432 bytes and 122 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 0 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-bio-control-destroy-115/collect.py --out work/bio-control-destroy-fresh
python3 -B research/work-items/RE-012-bio-control-destroy-115/verify.py --out work/bio-control-destroy-check-fresh.json
```
