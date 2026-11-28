# RE-002: Zlib length and distance table differences in node #115

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

All four complete linked tables in inflate_table match the libz-sys 1.1.22 source bundle. Three tables also match 1.1.31, whose lext differs at two entries. The verifier resolves the actual code reference for each table. This qualifies the table data and leaves library-wide revision attribution open.

Place libz-sys-1.1.22.crate, libz-sys-1.1.31.crate in an offline cache. Archive files come from the corresponding packages at static.crates.io and the checker verifies each digest. Run from the repository root with Python 3.9+.

```sh
python3 -B research/work-items/RE-002-node115-zlib-code-tables/verify.py /path/to/cache /path/to/binutils
```

The verifier reads the source and captured binary as data.
