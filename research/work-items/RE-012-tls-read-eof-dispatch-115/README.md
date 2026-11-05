# RE-012: map node115 TLS read retry and zero-length return dispatch

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

This read wrapper zeroes the count before SSL_read_ex.
A positive return uses the returned count and tag zero.
Nonpositive returns are classified. The high-bit-plus-two
form returns its payload under tag zero.

Class two can retry the same buffer and length, with error
cleanup when required by the record representation. Class
five and six have distinct dispatch before that retry.
A high-bit-plus-one record in either class takes the shared
zero-length success path. Class six also reaches that path
after dropping a high-bit error payload. Other outcomes use
the error return and its cleanup or conversion. No live
TLS session was run.

The retained 1 full FDEs cover 725 bytes and 193 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 6 instruction/data windows, 0 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-tls-read-eof-dispatch-115/collect.py --out work/tls-read-eof-dispatch-fresh
python3 -B research/work-items/RE-012-tls-read-eof-dispatch-115/verify.py --out work/tls-read-eof-dispatch-check-fresh.json
```
