# Preserve the exact checkpoint null-output sentinel

The integrated ABCI checkpoint classifier used Rust `Path` equality for `/dev/null`. That equality collapses redundant separators, interior dot components and trailing slashes. The Linux x86-64 #115 serializer compares the original path bytes, so only the literal spelling selects the no-output branch. The public Rust classifier now compares the underlying `OsStr` for this check and still uses normal path extension handling for the serializer choice.

| Stage | #115 anchor |
| --- | --- |
| Read original pointer and length | `0x26a2c9e–0x26a2ca5` |
| Compare nine bytes and select no output | `0x26a2cda–0x26a2d03`. The immediate supplies the first eight bytes and the XOR at `0x26a2cf6` compares the final `l`. The match jumps to `0x26a2f09`. |
| Continue to format selection | `0x26a2da4–0x26a2db8`. The length-three suffix at `0x4659e5` is `rmp`. The false comparison branch enters the JSON path at `0x26a2e1b`. |

The [snapshot output packet](../RE-009-node115-snapshot-null-output/README.md) established the corresponding static fast path in the worker helpers. This patch corrects the Rust entry point for ABCI serializer format selection and exercises it with path values alone. The fixtures do not open or write any of the paths.

## Reproduce

Target SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Run from the repository root.

```sh
python3 -B research/work-items/RE-009-node115-abci-exact-null-output/verify.py
cargo test --offline --locked --manifest-path src/node115-abci/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-abci/Cargo.toml --test integration checkpoint_output_requires_exact_null_path_spelling
```

The [offline log](offline-log.txt) includes the baseline failure for `/dev//null`, the full debug suite and the optimized focused regression. The static verifier reads the pinned ELF as data.
