# RE-002: httparse character class tables in node #115

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

The three complete 256-byte maps for ordinary HTTP character classes match pinned source data. One independently decoded operand selects each table. The packet covers only static data and references.

Place httparse-1.9.4.crate from static.crates.io in the offline cache. The verifier
checks the archive digests and reads the captured ELF as data. Run from the
repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-httparse-character-class-tables/verify.py /path/to/cache
```
