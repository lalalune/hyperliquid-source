# RE-009: Canonical height paths in the latest checkpoint loaders

Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `cfeaee133b33ce9450a7434af19515b82171a8c6`. All code addresses are
ELF virtual addresses.

Both latest-checkpoint loaders call the same numeric path generator already
traced for the [exact-height restore](../RE-017-node115-restore-canonical-heights/README.md).
Instructions `0x4468fee/0x4468ff1` and `0x59ffc1a/0x59ffc1d` pass zero
suffix length to slot `0x64e1208 -> 0x15623e0`. That provider collects
unsigned numeric values and renders path rows with the decimal formatter.
The marker check receives the rendered row in each loader. For example,
a completion marker below `00099` alone does not yield a completed
checkpoint at height 99. The test uses real directories and compares that
case against a regular marker under canonical `42`.

The one-byte sign guards in each loader are preceded by a comparison to a
length of one. Longer strings branch around those guards and the later
parse loop adjusts the pointer and remaining count by one for a leading
plus. A lone sign and negative or overflowing values remain invalid. The
prior [storage inventory paragraph](../RE-009-node115-storage-db-closure/README.md)
summarized the sign guard without the length precondition.

The Rust latest-checkpoint path now retains numeric heights and tests
completion at their rendered paths. It reuses the standard unsigned
parser, preserving errors for invalid values. Marker contents, payload
integrity, symlink/IO race semantics and the separate required subdirectory
predicate are outside this result. Existing marker checks are reused.
No captured instructions run.

From the repository root:

```sh
python3 -B research/work-items/RE-009-node115-latest-checkpoint-canonical-paths/verify.py
cargo test --locked --offline --manifest-path src/node115-db/Cargo.toml
```

See [raw output](offline-log.txt) for the failing baseline on the new test
and passing tests after the repair, and [instruction spans](windows.txt).
