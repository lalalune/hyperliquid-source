# RE-012: map node115 TLS connect BIO attachment and pending result

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The initial connect adapter first calls the BIO constructor.
The success sentinel installs the BIO on the SSL object and
enters SSL_connect. Positive return or classifier
high-bit-plus-two produces tag three with SSL and method
pointers. Other classifications retain the pair in the
expanded error record and choose tag two for classes two
or three, otherwise tag one.

On the BIO construction error branch it frees the supplied
SSL pointer before publishing the constructor error. The
scope covers attachment and initial ownership transfer.
A subsequent handshake resume is a separate path.

The retained 1 full FDEs cover 355 bytes and 89 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-tls-connect-bio-handoff-115/collect.py --out work/tls-connect-bio-handoff-fresh
python3 -B research/work-items/RE-012-tls-connect-bio-handoff-115/verify.py --out work/tls-connect-bio-handoff-check-fresh.json
```
