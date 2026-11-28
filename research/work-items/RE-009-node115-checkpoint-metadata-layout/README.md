# RE-009 restore #115 offline checkpoint bundles with ordinary JSON spacing

The reconstructed Rust bundle loader looked for field names immediately followed by a colon. A standard JSON formatter can insert a space, tab, or newline between them. A fixture with those legal layouts failed to restore because the loader reported a missing height, despite the original data remaining intact.

The local reader now separates the quoted field name from the following separator and skips whitespace before and after the colon. The same handling applies to checkpoint metadata fields, the LtHash group names, and the existing hex and numeric fields inside each group. The writer and the checkpoint field values stay unchanged. This is a compatibility fix to the existing offline wrapper and makes no claim about full JSON decoding or native checkpoint byte equivalence.

The reproduction writes a checkpoint through the ordinary Rust bundle writer, reformats both JSON files while retaining all original values, and restores through the public entry point. The baseline fails with `CorruptPayload("height")`. The corrected loader restores the same height, round, hardfork metadata, and all three LtHash records, including a nonempty recorded accumulator. All eleven tests in the integrated offline ABCI crate pass. [Actual baseline and corrected Rust output](offline-log.txt)

## Reproduce

From the repository root, using Rust 1.95 and the checked-in dependency lock:

```sh
cargo test --manifest-path src/node115-abci/Cargo.toml --offline --locked checkpoint_restore_accepts_json_spacing_around_colons
cargo test --manifest-path src/node115-abci/Cargo.toml --offline --locked
```

Source base `2da45cb0a761cff6b478e40421699857d87a94df`. The reconstructed component targets Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. No native execution is needed for this host compatibility check.
