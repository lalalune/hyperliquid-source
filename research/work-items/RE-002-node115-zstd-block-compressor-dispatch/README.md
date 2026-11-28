# RE-002: Zstandard block compressor dispatch matrices in node #115

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

Both source matrices match the linked null and alias pattern. All 45 nonzero RELATIVE addends land on FDE starts. Six instruction sites select the two bases. Full callee bodies and individual source symbol attribution are outside this comparison.

Place zstd-sys-2.0.13+zstd.1.5.6.crate from static.crates.io in the offline cache. The verifier
checks the archive digests and reads the captured ELF as data. Run from the
repository root with Python 3.9 or later and GNU readelf.

```sh
python3 -B research/work-items/RE-002-node115-zstd-block-compressor-dispatch/verify.py /path/to/cache /path/to/binutils
```
