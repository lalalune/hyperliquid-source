# Require a regular payload when selecting a local runtime checkpoint

The local reconstructed runtime selected a numbered checkpoint when its completion marker existed and the `checkpoint.bin` path was present. A directory at that path could win selection and stop restart before an older usable checkpoint was reached. Runtime selection now requires a regular payload file. The generic database helper continues to accept an existing directory when a caller requests a subdirectory.

The [native local-state reader packet](../RE-017-local-state-restore-115/README.md) recorded the path check at `0x2cc1232` before the selected native reader. That check uses `0x64e0950 → 0x1500d20`. The callee tests for a regular-file mode. A false result jumps around the reader at `0x2cc1249`. The reconstructed `checkpoint.bin` name, bincode payload and latest-selection fallback are local runtime behavior. The native anchor establishes the file-type separation before read, not equivalence of the two formats or fallback policies.

The regression persists a normal local checkpoint, creates a higher numbered directory with a completion marker and a directory named `checkpoint.bin`, and reopens the runtime. It checks the selected height and both instances of the reconstructed state root.

## Reproduce

Linux x86-64 node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Run from the repository root.

```sh
python3 -B research/work-items/RE-017-node115-runtime-checkpoint-payload/verify.py
cargo test --offline --locked --manifest-path src/hl-node/Cargo.toml --test checkpoint_payload_type
cargo test --offline --locked --manifest-path src/node115-db/Cargo.toml
```

The [offline log](offline-log.txt) records the baseline I/O failure and the passing checks. The fixture uses only local temporary directories.
