# RE-002: chrono fixed-offset formatting in node #115

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

Compare the full catalogued fixed-offset Debug formatter outside relocation fields and check its sign and base-60 operations against pinned public chrono source.

Place chrono-0.4.38.crate in the source cache. Run from the repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-chrono-fixed-offset-debug-format/verify.py /path/to/cache
```
