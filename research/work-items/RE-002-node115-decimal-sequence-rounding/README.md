# RE-002: binary64 decimal sequence rounding in node #115

Target Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df. Licensed Rust 1.95.0 release source commit 59807616e1fa2540724bfbac14d7976d7e4a3860 and rust-src SHA-256 67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363.

All 249 bytes of DecimalSeq::round match the pinned Rust source build without relocation masking. The function rounds the parser’s decimal digit sequence to an integer with ties to even. This covers the linked numeric helper separately from the application-level decimal conversion and the already matched left and right shifts.

Provision the offline cache using RE-002-node115-umodti3-source-build. Rebuild
core with the default release profile. Run with Python 3.12 and GNU
binutils 2.42 from the repository root.

```sh
python3 -B research/work-items/RE-002-node115-decimal-sequence-rounding/verify.py /path/to/cache /path/to/binutils
```
