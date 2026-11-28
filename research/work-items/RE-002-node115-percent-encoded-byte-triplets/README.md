# RE-002: percent-encoded byte triplets in node #115

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

The 256 uppercase percent-encoded triplets match their complete 768-byte source literal in byte order. Three linked instruction sites reference the array. The related URL path and query bitmaps decide when to encode and are separate tables.

Place percent-encoding-2.3.1.crate from static.crates.io in the offline cache. The verifier
checks the archive digest and reads the captured ELF as data. Run from the
repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-percent-encoded-byte-triplets/verify.py /path/to/cache
```
