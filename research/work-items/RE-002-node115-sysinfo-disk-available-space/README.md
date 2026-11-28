# RE-002: sysinfo disk available-space refresh in node #115

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

Compare the catalogued disk refresh body outside recorded relocation fields, resolve its statvfs import, and bind the available-space calculation to pinned public sysinfo source.

Place sysinfo-0.29.11.crate in the source cache and run from the repository root with Python 3.9 or later and GNU readelf.

```sh
python3 -B research/work-items/RE-002-node115-sysinfo-disk-available-space/verify.py /path/to/cache /path/to/binutils
```
