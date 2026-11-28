# RE-002: sysinfo memory refresh source paths in node #115

Linux x86-64 node #115. SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

The seven ordinary memory refresh path literals selected in the linked Linux body match the pinned source list in order. This identifies the procfs and cgroup v1/v2 input coordinates without reading those files.

Place the release archive sysinfo-0.29.11.crate in the local source cache. Run
from the repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-sysinfo-memory-refresh-source-paths/verify.py /path/to/cache
```
