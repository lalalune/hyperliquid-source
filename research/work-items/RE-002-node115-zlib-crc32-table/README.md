# RE-002: zlib CRC-32 table in node #115

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

Compare the complete 256-entry IEEE CRC-32 lookup table with pinned public zlib source and check two direct references. The captured target stores entries as 64-bit words.

Place libz-sys-1.1.22.crate in the source cache and run from the repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-zlib-crc32-table/verify.py /path/to/cache
```
