# RE-012: map node115 OpenSSL error display field admission

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The display wrapper loads the saved error code from +0x28
and emits it before consulting ERR_lib_error_string. A null
library string skips that field; a nonnull string is measured
and passed to the text checker before formatting.

The optional string at +0x30 is checked using length at +0x38
minus one. The wrapper separately consults ERR_reason_error_string
with the same error code, skipping null and validating the
nonnull span. It then projects the saved file string with
its terminator excluded. These are formatting and field
admission paths after error collection. The packet retains
the invalid-text branch targets and exact library bindings.

The retained 1 full FDEs cover 789 bytes and 169 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 0 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-openssl-error-display-fields-115/collect.py --out work/openssl-error-display-fields-fresh
python3 -B research/work-items/RE-012-openssl-error-display-fields-115/verify.py --out work/openssl-error-display-fields-check-fresh.json
```
