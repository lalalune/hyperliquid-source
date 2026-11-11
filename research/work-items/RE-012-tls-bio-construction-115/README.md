# RE-012: map node115 OpenSSL BIO construction and failure ownership

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The selected constructor allocates a BIO method and registers
write, read, puts, ctrl, create and destroy callbacks in that
order. Setter returns are checked individually. Failure paths
converge through the local error collection and method release
when a method object exists.

The BIO_new success path installs the allocated state with
BIO_set_data and sets init to one. It publishes the BIO pointer
and method pointer at result +8/+16. The BIO_new failure path
collects an error, drops and releases the 0x48-byte state, and
frees the method. This packet isolates transport object ownership.
Callback behavior and network I/O are separate scopes.

The retained 1 full FDEs cover 831 bytes and 197 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 6 instruction/data windows, 3 RELATIVE addends, 11 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-tls-bio-construction-115/collect.py --out work/tls-bio-construction-fresh
python3 -B research/work-items/RE-012-tls-bio-construction-115/verify.py --out work/tls-bio-construction-check-fresh.json
```
