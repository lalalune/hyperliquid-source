# RE-002: Zstandard sequence encoding cost table in node #115

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

All 256 unsigned inverse-probability log values match 1,024 linked bytes. The five code reference fields resolve to the source table. This concerns the encoder cost estimate rather than the default sequence decoder tables.

Place zstd-sys-2.0.13+zstd.1.5.6.crate from static.crates.io in the offline cache. The verifier
checks the archive digests and reads the captured ELF as data. Run from the
repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-zstd-sequence-cost-table/verify.py /path/to/cache
```
