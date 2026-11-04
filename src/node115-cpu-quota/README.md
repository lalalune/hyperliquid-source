# Node115 quota/cache value projection

The independent implementation covers successful parsed quota/period inputs,
selected atomic publication, supplied affinity-mask or sysconf results, and the
getter's precedence after any required once call has returned. It does not call
Linux, parse cgroups, implement Once, or recreate a private ABI.

See `research/work-items/RE-002-cpu-quota-115/CONTRACT.md` for target bindings,
floating-environment assumptions, complete scope and historical oracle ancestry.

Run native unit tests with an installed Rust toolchain:

```sh
cargo test --locked --offline --manifest-path src/node115-cpu-quota/Cargo.toml \
  --target-dir work/cpu115-cargo
```

Run both installed compiler versions, four optimization builds and compiled
counterfactuals from the repository root; supply their actual executable paths:

```sh
python3 -B research/work-items/RE-002-cpu-quota-115/native/qualify.py \
  --rustc /path/to/rust-1.94.1/bin/rustc \
  --rustc /path/to/rust-1.95.0/bin/rustc \
  --out work/cpu115-native-review
```

This executes only the independent Rust program, never captured instructions.
Source is MIT; public upstream interpretive material retains its own licenses.
