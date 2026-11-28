# RE-002: HTTP/2 settings debug fields in node #115

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

Compare the catalogued h2 Settings Debug body outside recorded relocation fields and verify its structure name and all eight emitted field labels against pinned public h2 source.

Place h2-0.3.26.crate in the source cache and run from repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-h2-settings-debug-fields/verify.py /path/to/cache
```
