# RE-002: HTTP2 Reason debug names in node #115

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

All 14 public source reason labels match the selected linked addresses and length records. This checks human-readable Debug output data.

Place h2-0.4.13.crate from static.crates.io in the offline cache. The verifier
checks the archive digests and reads the captured ELF as data. Run from the
repository root with Python 3.9 or later and GNU readelf.

```sh
python3 -B research/work-items/RE-002-node115-h2-reason-debug-names/verify.py /path/to/cache /path/to/binutils
```
