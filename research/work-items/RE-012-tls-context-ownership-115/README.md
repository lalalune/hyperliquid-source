# RE-012: map node115 SSL context result and partial construction cleanup

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The context builder passes the selected method to SSL_CTX_new.
Null allocation takes error collection. A collected error
returns without freeing a context; the high-bit sentinel
takes the explicit continuation retained in the export.

After context construction, the default-path call and the
following list helper have independent status paths. A
populated error record is moved to the caller before
SSL_CTX_free. The successful path stores the context pointer
at +8 under the high-bit sentinel. The packet covers
ownership and output shape. It does not evaluate trust
configuration or negotiate a connection.

The retained 1 full FDEs cover 381 bytes and 91 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 1 RELATIVE addends, 4 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-tls-context-ownership-115/collect.py --out work/tls-context-ownership-fresh
python3 -B research/work-items/RE-012-tls-context-ownership-115/verify.py --out work/tls-context-ownership-check-fresh.json
```
