# RE-002: LZ4 stream decode dictionary setup in node #115

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

Compare the full catalogued stream decode dictionary initializer and check its prefix and external-dictionary stores against the pinned public LZ4 source.

Place lz4-sys-1.11.1+lz4-1.10.0.crate in the source cache and run from the repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-lz4-stream-decode-dictionary/verify.py /path/to/cache
```
