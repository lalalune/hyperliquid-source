# RE-002: sysinfo disk rotational path construction in node #115

Linux x86-64 node #115. SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

The public Linux disk attribute path is checked from its source parameters through the actual immediate stores and linked suffix literal. Both parts and lengths are bound to their common join destination.

Place sysinfo-0.29.11.crate in the local source cache. Run from the repository
root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-sysinfo-disk-rotational-path/verify.py /path/to/cache
```
