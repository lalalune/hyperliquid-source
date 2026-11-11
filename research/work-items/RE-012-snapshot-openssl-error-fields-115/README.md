# RE-012: recover node #115 OpenSSL error field provenance and validation

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The OpenSSL error-row formatter begins with the literal Error and passes the code, library, function and reason fields to the field-writer adapter. The library and reason labels are obtained from the code through the distinct OPENSSL_3.0.0 imports ERR_lib_error_string and ERR_reason_error_string. A null label bypasses the corresponding strlen call. A present label is length-measured and passed through the shared UTF-8 validator; tag one branches to the diagnostic for that field. Function text also crosses the UTF-8 validator, but it comes from the row rather than an OpenSSL string lookup. This packet maps field provenance and validation before the field writers, separate from the caller's row traversal.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-openssl-error-fields-115/collect.py --out work/node115-snapshot-openssl-error-fields-fresh
python3 -B research/work-items/RE-012-snapshot-openssl-error-fields-115/verify.py --out work/node115-snapshot-openssl-error-fields-check-fresh.json
```
