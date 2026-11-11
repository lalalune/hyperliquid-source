# RE-012: map node115 borrowed socket address queries and length guards

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The local and peer queries take a borrowed fd. They use distinct
dynamic imports and the same selected address projection. Each
passes a zeroed 128-byte address buffer and a length initialized
to 128. A return of -1 yields tag two and the packed errno at +8.

For family 2 the wrapper guards length >=16, stores a zero family
tag, copies the address dword to +2 and stores the byte-swapped
port at +6. For family 10 it guards length >=28, writes tag one,
retains the 16 address bytes and copies the separate source words
at offsets +4 and +24. The port is byte-swapped into result +0x1c.
Short results take distinct diagnostic calls. Other families take
the static error payload path with tag two. This scope follows
borrowed address queries and does not include accept ownership.

The retained 2 full FDEs cover 670 bytes and 160 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 8 instruction/data windows, 0 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-socket-address-query-115/collect.py --out work/socket-address-query-fresh
python3 -B research/work-items/RE-012-socket-address-query-115/verify.py --out work/socket-address-query-check-fresh.json
```
