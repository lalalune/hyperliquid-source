# Node #115 tagged-count projection

A dependency-free, independently authored Rust implementation of the scalar
relation observed in three complete 69-byte #115 functions. The full-width zero
tag, low-32-bit one tag, saturating unsigned subtraction and unsigned cap are
preserved. The API accepts raw values; original object types, callers and ABI
remain unclaimed.

```sh
cargo +1.95.0 test --offline --locked --manifest-path src/node115-tagged-count/Cargo.toml
python3 tools/node115_tagged_count.py --build-dir work/tagged-count-check
```

See [the target records and frozen corpus](../../research/work-items/RE-001-node115-tagged-count/README.md).
No compiled byte-equality or whole-component completion claim is made.
