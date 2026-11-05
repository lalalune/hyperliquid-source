# RE-012: map node115 interface link entry projection and list release

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The linked-list walk reads the next pointer before inspecting
the address. A null address or family other than 0x11 skips
the link record. The admitted branch reads four bytes at
address +0xc and two bytes at +0x10.

The wrapper allocates a 22-byte name buffer, calls strcpy
and measures the source name. It packages the byte fields
and owned name for the selected insertion path. Ordinary
completion frees the original interface list. The visible
unwind edges also free that list, with the name allocation
released on the path where it is locally owned. Scope is the
link-record projection, separate from list acquisition.

The retained 1 full FDEs cover 673 bytes and 165 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-interface-link-projection-115/collect.py --out work/interface-link-projection-fresh
python3 -B research/work-items/RE-012-interface-link-projection-115/verify.py --out work/interface-link-projection-check-fresh.json
```
