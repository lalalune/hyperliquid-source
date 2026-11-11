# RE-012: map node115 SSL context reference and extra-data handoff

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The wrapper checks the extra-data index initialization state.
If needed it calls the initializer and proceeds only on the
success marker. SSL_new failure collects and returns the error.

For a nonnull SSL pointer it increments the supplied context
reference and reads the extra-data slot. An existing slot
releases the previous context and replaces its pointer.
An absent slot allocates a pointer-sized cell and passes it
to SSL_set_ex_data. The ordinary return publishes the high-bit
marker and SSL pointer. This scope concerns ownership, not
TLS negotiation.

The retained 1 full FDEs cover 292 bytes and 78 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 2 RELATIVE addends, 5 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-ssl-context-reference-handoff-115/collect.py --out work/ssl-context-reference-handoff-fresh
python3 -B research/work-items/RE-012-ssl-context-reference-handoff-115/verify.py --out work/ssl-context-reference-handoff-check-fresh.json
```
