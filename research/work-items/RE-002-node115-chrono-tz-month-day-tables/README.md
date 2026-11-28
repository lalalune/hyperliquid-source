# RE-002: Chrono timezone month-day tables in node #115

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

The normal-year month lengths and cumulative month-day arrays each reproduce 96 source-defined bytes. Three source-consistent linked references select the two bases. This scope concerns the local-timezone rule calendar and is separate from the 400-year NaiveDate table.

Place chrono-0.4.38.crate from static.crates.io in the offline cache. The verifier
checks the archive digests and reads the captured ELF as data. Run from the
repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-chrono-tz-month-day-tables/verify.py /path/to/cache
```
