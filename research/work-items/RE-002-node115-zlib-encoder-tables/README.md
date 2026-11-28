# RE-002: Zlib default encoder tables in node #115

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

The checker compares the full linked contents of the encoder length and distance code arrays, base length and distance arrays, and both static encoding trees. It also checks a linked instruction reference per table. The verified structures belong to the compression side.

Place the published libz-sys-1.1.22.crate archive from static.crates.io in an offline cache. The checker verifies its archive digest. Run from the repository root with Python 3.9+.

```sh
python3 -B research/work-items/RE-002-node115-zlib-encoder-tables/verify.py /path/to/cache /path/to/binutils
```

The verifier reads the crate and the captured binary as files.
