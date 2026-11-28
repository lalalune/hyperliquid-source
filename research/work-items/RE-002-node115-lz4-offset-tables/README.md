# RE-002: LZ4 overlap offset tables in node #115

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

The verifier reconstructs the two eight-entry integer arrays from the pinned LZ4 source. It checks thirty-two linked bytes in each array and two RIP-relative references per array. Previous work describes stream setup and native decode callers.

Place lz4-sys-1.9.4.crate in an offline cache. Archive files come from the corresponding packages at static.crates.io and the checker verifies each digest. Run from the repository root with Python 3.9+.

```sh
python3 -B research/work-items/RE-002-node115-lz4-offset-tables/verify.py /path/to/cache /path/to/binutils
```

The verifier reads the source and captured binary as data.
