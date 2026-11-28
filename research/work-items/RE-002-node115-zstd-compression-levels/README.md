# RE-002: Zstandard compression level matrix in node #115

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

The source matrix specifies four groups of 23 compression parameter records. Packing the source values and strategy enum reproduces 2,576 target bytes. Two RIP-relative references lead to its linked base. This packet checks encoder settings, separately from decode tables.

Place the published zstd-sys-2.0.13+zstd.1.5.6.crate archive from static.crates.io in an offline cache. The checker verifies its archive digest. Run from the repository root with Python 3.9+.

```sh
python3 -B research/work-items/RE-002-node115-zstd-compression-levels/verify.py /path/to/cache /path/to/binutils
```

The verifier reads the crate and the captured binary as files.
