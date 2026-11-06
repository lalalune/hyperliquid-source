# RE-012: map node115 TLS handshake resume result handoff

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The resume adapter takes the SSL pointer from pending record
+0x20 and calls SSL_do_handshake. A positive return or a
classified high-bit-plus-two result produces tag three and
moves the SSL pointer and method pointer to the output.

The success arm releases the previous error storage according
to its representation. The continuation for a fresh error
also disposes of the prior error before copying the new one
into the pending record. It retains the SSL/method pair and
selects output tag two for classes two or three, otherwise
tag one. This scope covers repeat handshake calls and pending
record ownership, separate from initial BIO attachment.

The retained 1 full FDEs cover 654 bytes and 180 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-tls-handshake-resume-115/collect.py --out work/tls-handshake-resume-fresh
python3 -B research/work-items/RE-012-tls-handshake-resume-115/verify.py --out work/tls-handshake-resume-check-fresh.json
```
