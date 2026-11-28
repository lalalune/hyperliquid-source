# RE-002: address parse error format data in node #115

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

All six source-defined address parse diagnostic strings match the linked
length table and six dynamic string pointer relocations. The dispatcher at
0x16893b0 references both tables and resolves its formatter destination.
A similar candidate at 0x5aabaf0 references different length data.

Use the pinned Rust 1.95.0 source archive provisioned using
RE-002-node115-umodti3-source-build. With Python 3.9+ and GNU readelf, run
from the repository root.

```sh
python3 -B research/work-items/RE-002-node115-address-error-format-data/verify.py /path/to/cache /path/to/binutils
```
