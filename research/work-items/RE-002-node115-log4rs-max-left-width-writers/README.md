# RE-002: log4rs maximum and left width writers in node #115

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

Compare catalogued maximum-width and left-alignment writer bodies outside recorded relocation fields, and verify their character-boundary and remaining-width operations against pinned public source.

Place log4rs-1.3.0.crate in the source cache and run from the repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-log4rs-max-left-width-writers/verify.py /path/to/cache
```
