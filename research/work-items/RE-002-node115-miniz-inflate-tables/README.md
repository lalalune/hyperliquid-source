# RE-002: Rust miniz_oxide inflater tables in node #115

Linux x86-64 node #115. SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

Four complete Rust arrays match 162 linked bytes. Seven code references
establish that the matching data is used. The length base, extra-bit and
distance arrays each have two references. The minimum table sizes array
has one. Earlier std debug-info evidence stops at the call into the inflater.
This packet covers static constants and their linked references.

Place the pinned `miniz_oxide-0.8.9.crate` from static.crates.io in a source
cache. Run with Python 3.9 or later from the repository root.

```sh
python3 -B research/work-items/RE-002-node115-miniz-inflate-tables/verify.py /path/to/cache
```
