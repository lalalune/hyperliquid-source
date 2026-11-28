# RE-002: Unicode width tables in node #115

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

Compare all three Unicode width lookup tables with the pinned public source archive, and verify the three linked GOT relocations and caller references.

Place unicode-width-0.1.13.crate in the source cache. Run with Python 3.9 or later and GNU readelf.

```sh
python3 -B research/work-items/RE-002-node115-unicode-width-three-level-tables/verify.py /path/to/cache /path/to/binutils
```
