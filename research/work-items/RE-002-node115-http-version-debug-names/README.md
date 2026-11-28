# RE-002: HTTP version debug names in node #115

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

Compare the catalogued HTTP Version Debug body outside recorded relocation fields and verify all five version strings and jump targets against pinned public source.

Place http-0.2.12.crate in the source cache and run from the repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-http-version-debug-names/verify.py /path/to/cache
```
