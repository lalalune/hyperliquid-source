# RE-012: map node115 accept4 descriptor and peer address handoff

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The wrapper passes the listener fd, stack address storage, a length
initialized to 128, and flags 0x80800 to accept4. A negative return
sets output tag 1 and stores (errno << 32) | 2 at +8.

Success dispatches on family 2 or 10. Family 2 copies the address
dword at source +4 and rotates the port word by 8 bits. Family 10
copies the 16 address bytes from source +8 in three parts, rotates
the port, and takes separate dwords at source +4 and +24. The
shared result stores the accepted fd at +4, family discriminator
0 or 1 at +8, and clears output tag +0. The exports retain exact
stores, including fields which are not assigned semantic meaning
in the family-2 arm.

An unsupported family sets tag 1 and payload 0x1400000003, closes
the newly accepted descriptor and returns the output pointer.
The packet covers the wrapper's ownership and layout, independent
of the listener construction and the kernel's accept behavior.

The retained 1 full FDEs cover 260 bytes and 64 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 0 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-accept4-address-handoff-115/collect.py --out work/accept4-address-handoff-fresh
python3 -B research/work-items/RE-012-accept4-address-handoff-115/verify.py --out work/accept4-address-handoff-check-fresh.json
```
