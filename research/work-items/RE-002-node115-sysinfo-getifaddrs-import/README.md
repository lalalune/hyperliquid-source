# RE-002: sysinfo interface address import in node #115

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

Compare the full catalogued interface-address helper outside relocation fields. Resolve its getifaddrs and errno imports and compare the source-level retry and null handling in the pinned public archive.

Place sysinfo-0.29.11.crate in the source cache. Run from the repository root with Python 3.9 or later and GNU readelf.

```sh
python3 -B research/work-items/RE-002-node115-sysinfo-getifaddrs-import/verify.py /path/to/cache /path/to/binutils
```
