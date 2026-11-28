# RE-002: Zlib fixed Huffman decode tables in node #115

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

The complete 512-entry literal/length table and 32-entry distance table match the generated fixed-code header. The checker follows two independently decoded instruction references and rejects modified entries. Earlier length/distance proof checks the numeric bases used to generate dynamic tables.

Place the published libz-sys-1.1.22.crate archive from static.crates.io in an offline cache. The checker verifies its archive digest. Run from the repository root with Python 3.9+.

```sh
python3 -B research/work-items/RE-002-node115-zlib-fixed-decode/verify.py /path/to/cache /path/to/binutils
```

The verifier reads the crate and the captured binary as files.
