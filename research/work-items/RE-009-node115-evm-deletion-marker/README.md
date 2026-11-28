# Require a regular EVM checkpoint deletion marker

The reconstructed EVM checkpoint filter let any filesystem entry named `MARKED_FOR_DELETION` bypass the normal height bounds. A directory at that path therefore bypassed the bounds in the local fixture. The #115 filter checks file type. The Rust classifier now tests for a regular file and keeps the existing height comparisons and outcome variants.

At `0x3d5dd85` the filter prepares the marker path with the format record at `0x44c7fa`. The call at `0x3d5dda4` resolves through `0x64e0950` to `0x1500d20`. The predicate's metadata-success path masks the file mode with `0xf000` and compares it with the regular-file constant `0x8000`. The true branch bypasses height comparisons and appends the row at `0x3d5dd00`. The false branch reaches the lower, exclusive upper and inclusive maximum bounds. The [prior maintenance study](../RE-015-evm-prune-policy-115/README.md) covers the surrounding mode and caller policy. Its marker predicate was left as an operating-system boundary.

The test changes a marker-shaped directory into an empty regular marker inside temporary fixture storage and independently exercises both across five heights. The classifier performs metadata reads. The test does not execute any checkpoint-maintenance command.

## Reproduce

Linux x86-64 node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Run from the repository root.

```sh
python3 -B research/work-items/RE-009-node115-evm-deletion-marker/verify.py
cargo test --offline --locked --manifest-path src/node115-abci/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-abci/Cargo.toml --test integration evm_deletion_marker_requires_regular_file_before_bypassing_height_checks
```

The [offline log](offline-log.txt) includes the baseline mismatch and both passing runs. The verifier reads the pinned ELF as data.
