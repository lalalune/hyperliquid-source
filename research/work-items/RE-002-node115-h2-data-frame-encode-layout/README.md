# RE-002: h2 DATA frame encode layout in node #115

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

Compare four catalogued DATA chunk encoders outside recorded relocation fields, and check the header field widths and byte-order instructions against pinned public h2 source.

Place h2-0.3.26.crate in the source cache and run from the repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-h2-data-frame-encode-layout/verify.py /path/to/cache
```
