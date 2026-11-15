# node115-shortstring-intern

Independent Rust model of two node #115 pieces (ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`):

- the name-to-`u128` key function at `0x1546aa0` (`base/src/short_string.rs`): names of at most 16 bytes pack little-endian; a longer name becomes ten letters `'A' + SipHash-1-3(name || 0xff || i32 LE) % 26` (zero key, `i = 0..10`), packed the same way, with a process-wide name map that stops taking new names at 100,000 entries. The key is ten capital letters, so different names can share a key (the 17-byte `abcdefghijklmnopq` and the 10-byte `XGOKOCQCLX` do, in this model);
- the row builder at `0x155cd10` (`base/src/cid.rs`) that calls it for each item *before* a separate 20-byte text parser.

Static reconstruction: the target was never run, no behavioural equivalence with the node is claimed, and the map's concurrency, locking and allocation are not modelled. The 20-byte parser (`0x150d640`) is not reconstructed: `build_rows` takes it as a parameter, and the tests use a stand-in.

Evidence, address table, credit to prior packets and the reproduce commands are in
[`research/work-items/RE-001-node115-shortstring-intern-cid-key`](../../research/work-items/RE-001-node115-shortstring-intern-cid-key/README.md) (cross-reference; that packet is this crate's evidence).
The 89-byte fold at `0x15472b0` is `RE-001-node115-shortstring-le-u128-fold`'s finding; `fold_le_u128` here re-implements its recurrence because no crate existed.

```sh
cargo test --offline --manifest-path src/node115-shortstring-intern/Cargo.toml --target-dir work/shortstring/target
```

The tests replay `research/work-items/RE-001-node115-shortstring-intern-cid-key/corpus.txt` (override with `SHORTSTRING_CORPUS`). They are **not collected by `make test`** (that runs Python tests); the line above is the manual command. Std only, no dependencies, own `[workspace]`.

API: `KeyCache::key_for(&str) -> Keyed { key, path }`, `generated_name`, `SipHasher13`, `fold_le_u128`, `build_rows`. `Path` is the model's report of which branch ran, not a node output.
