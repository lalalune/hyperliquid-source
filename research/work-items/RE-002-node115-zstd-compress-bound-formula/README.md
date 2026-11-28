# RE-002: Zstd compression bound formula in node #115

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

Compare the complete catalogued ZSTD_compressBound object with the node, and check the normal size-bound formula's shift and threshold instructions against the pinned published source archive.

Place zstd-sys-2.0.15+zstd.1.5.7.crate in the source cache and run from the repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-zstd-compress-bound-formula/verify.py /path/to/cache
```
