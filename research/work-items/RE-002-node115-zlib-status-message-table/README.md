# RE-002: zlib status message table in node #115

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

Ten linked pointers select the exact source strings in order, including the shared empty literal. Three text references select the array, with one independently checked ordinary buffer-status index.

Place libz-sys-1.1.22.crate from static.crates.io in the offline cache. The verifier
checks the archive digests and reads the captured ELF as data. Run from the
repository root with Python 3.9 or later and GNU readelf.

```sh
python3 -B research/work-items/RE-002-node115-zlib-status-message-table/verify.py /path/to/cache /path/to/binutils
```
