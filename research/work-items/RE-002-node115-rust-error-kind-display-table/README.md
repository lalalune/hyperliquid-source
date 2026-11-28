# RE-002: Rust ErrorKind display table in node #115

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

All 42 enum descriptions match the linked length and signed-offset tables in source order. Two code references bind their bases. This covers human-readable labels and is independent of Linux errno-to-enum conversion.

Place rust-src-1.95.0.tar.xz from the pinned Rust source release in the offline cache. The verifier
checks the archive digests and reads the captured ELF as data. Run from the
repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-rust-error-kind-display-table/verify.py /path/to/cache
```
