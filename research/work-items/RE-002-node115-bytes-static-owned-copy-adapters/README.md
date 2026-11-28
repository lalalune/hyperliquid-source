# RE-002: bytes static-slice owned-copy adapters in node #115

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

Compare the catalogued static-slice to Vec and BytesMut adapters outside recorded relocation fields. Verify both allocation and memcpy references against pinned public bytes source and the ELF dynamic import.

Place bytes-1.11.1.crate in the source cache and run from the repository root with Python 3.9 or later and GNU readelf.

```sh
python3 -B research/work-items/RE-002-node115-bytes-static-owned-copy-adapters/verify.py /path/to/cache /path/to/binutils
```
