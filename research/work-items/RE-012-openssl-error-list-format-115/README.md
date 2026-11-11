# RE-012: map node115 OpenSSL error list iteration and sink short-circuit

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The list formatter reads entry count and base from the
error record. Count zero tail-dispatches a fixed fallback
string to the sink. Otherwise it formats the first entry
before checking whether any additional entries exist.

For multiple entries the loop advances by 72 bytes, emits
a two-byte separator, and formats each subsequent entry.
A nonzero sink or formatter result returns the error
indicator without continuing. This packet scopes iteration
and sink failure, separate from individual entry display
and queue ownership.

The retained 1 full FDEs cover 274 bytes and 78 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 3 instruction/data windows, 1 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-openssl-error-list-format-115/collect.py --out work/openssl-error-list-format-fresh
python3 -B research/work-items/RE-012-openssl-error-list-format-115/verify.py --out work/openssl-error-list-format-check-fresh.json
```
