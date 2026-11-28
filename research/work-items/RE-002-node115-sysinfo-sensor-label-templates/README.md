# RE-002: sysinfo sensor label templates in node #115

Linux x86-64 node #115. SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

All four source format variants map to three complete linked templates. Two variants have the same formatting byte sequence with different field arguments. The verifier independently binds the three template addresses.

Place sysinfo-0.29.11.crate in the local source cache. Run from the repository
root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-sysinfo-sensor-label-templates/verify.py /path/to/cache
```
