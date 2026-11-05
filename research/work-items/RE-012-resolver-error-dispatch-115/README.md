# RE-012: map node115 getaddrinfo result and error dispatch

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The wrapper zeroes its addrinfo hints, sets the socket type
word to one and passes a null service to getaddrinfo. Status
zero publishes tag zero, the returned list pointer at +8 and
+16, and the caller's port word at +0x18.

Nonzero status runs the version-query helper and can call
__res_init when the selected version fields are below 2.26.
That call does not re-enter getaddrinfo. Status -11 takes
errno and packs it with low tag two. Other statuses go through
gai_strerror, strlen and the formatting helpers. Both error
routes set result tag one and payload +8. The packet scopes
the wrapper dispatch and does not make resolver requests.

The retained 1 full FDEs cover 428 bytes and 115 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 0 RELATIVE addends, 5 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-resolver-error-dispatch-115/collect.py --out work/resolver-error-dispatch-fresh
python3 -B research/work-items/RE-012-resolver-error-dispatch-115/verify.py --out work/resolver-error-dispatch-check-fresh.json
```
