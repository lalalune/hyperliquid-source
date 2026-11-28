# RE-002: Zstandard default sequence tables in node #115

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

The linked default LL, OF and ML sequence tables are packed into 163 eight-byte records, including their headers. Each complete table matches the pinned Zstandard source. Three RIP-relative sites from the sequence-header body identify the corresponding tables. Earlier native branch evidence covers outgoing calls.

Place zstd-sys-2.0.13+zstd.1.5.6.crate in an offline cache. Archive files come from the corresponding packages at static.crates.io and the checker verifies each digest. Run from the repository root with Python 3.9+.

```sh
python3 -B research/work-items/RE-002-node115-zstd-default-sequence-tables/verify.py /path/to/cache /path/to/binutils
```

The verifier reads the source and captured binary as data.
