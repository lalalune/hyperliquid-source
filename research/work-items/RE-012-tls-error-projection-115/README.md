# RE-012: map node115 SSL error class and BIO saved-error take

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The classifier reads BIO state through SSL_get_rbio and
BIO_get_data. It clears the saved pair pointer at +0x30
and routes a nonzero saved pointer to the separate helper.

The ordinary path calls SSL_get_error with the saved
operation result. Classes two and three take and clear
the saved error at BIO state +0x28. A nonzero error
changes the leading sentinel from high-bit-plus-one to
high-bit. Class one collects the OpenSSL error record.
Class five collects first and takes the BIO saved error
when that collection's count word is zero. The wrapper
publishes the class at +0x18 and retains the exact three
preceding word stores. This is error representation, not
a claim about TLS security or peer behavior.

The retained 1 full FDEs cover 325 bytes and 88 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 1 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-tls-error-projection-115/collect.py --out work/tls-error-projection-fresh
python3 -B research/work-items/RE-012-tls-error-projection-115/verify.py --out work/tls-error-projection-check-fresh.json
```
