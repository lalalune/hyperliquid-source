# RE-002: HTTP canonical status reasons in node #115

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

Compare the catalogued status-reason selector outside relocation fields. Decode its jump table and verify every in-range result against the published http 0.2.12 source. The captured mapping has no 425 reason, unlike the later 1.3.1 source, so this record makes no 1.3.1 version claim.

Place http-0.2.12.crate in the source cache and run from the repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-http-status-canonical-reasons/verify.py /path/to/cache
```
