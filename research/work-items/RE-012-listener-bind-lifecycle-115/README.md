# RE-012: map node115 listener bind and failure ownership

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The listener wrapper creates a socket of type 0x80801 and uses
setsockopt with level 1, option 2, a four-byte value of one.
It constructs separate family-2 and family-10 sockaddr layouts
of lengths 16 and 28, with a byte-swapped port. The successful
bind is followed by listen with backlog 128.

A failed socket call writes an errno payload and tag one without
a close. A failed setsockopt, bind, or listen takes the descriptor
cleanup route, which writes (errno << 32) | 2 before closing the
descriptor. Only successful listen publishes tag zero and the
fd at +4. This isolates construction and ownership before the
separately mapped accept call.

The retained 1 full FDEs cover 305 bytes and 81 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 6 instruction/data windows, 0 RELATIVE addends, 6 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-listener-bind-lifecycle-115/collect.py --out work/listener-bind-lifecycle-fresh
python3 -B research/work-items/RE-012-listener-bind-lifecycle-115/verify.py --out work/listener-bind-lifecycle-check-fresh.json
```
