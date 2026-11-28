# RE-002: zlib length and distance mapping tables in node #115

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

Compare the complete length and distance code lookup arrays and base-value arrays against pinned public zlib source, and verify a representative direct reference to each table. The Huffman trees are covered by #7313.

Place libz-sys-1.1.22.crate in the source cache and run from the repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-zlib-static-huffman-tables/verify.py /path/to/cache
```
