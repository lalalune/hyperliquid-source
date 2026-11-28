# RE-002: SHA-512 round constants in node #115

Linux x86-64 node #115. SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

All eighty 64-bit round constants match the public RustCrypto SHA-2 archive pinned in the repository candidate lockfile. Two linked RIP-relative references name the matching bytes. The match identifies standard algorithm data and leaves compiler and source-object provenance open.

Place `sha2-0.10.8.crate` from static.crates.io in a source cache. The verifier
checks the archive digest and reads the captured ELF as data. Run with
Python 3.9 or later from the repository root.

```sh
python3 -B research/work-items/RE-002-node115-sha512-round-constants/verify.py /path/to/cache
```
