# RE-002: zlib inflate reset state in node #115

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

Compare the catalogued inflateReset body outside registered relocation fields. Check window-state zeroing and reset distance limit alongside the pinned public source.

Place libz-sys-1.1.22.crate in the source cache and run from the repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-zlib-inflate-reset-state/verify.py /path/to/cache
```
