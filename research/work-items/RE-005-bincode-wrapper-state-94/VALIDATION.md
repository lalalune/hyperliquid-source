# Actual validation

All results below concern the pinned node94 input and independently authored
host Rust. No captured binary, instruction interpreter or live network ran.
Root repository gates and hosted CI are reported separately by the coordinator.

## Before and after

The original component source at base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`
has SHA-256 `96a4b43f42ff54524bf36279e24e0ee30771223de4486f189c77b6a86dd0a279`.
Its real library compiles, but the new wrapper driver fails compilation because
`SliceDecoder` and `SliceError` do not exist. The original source matches the
hash recorded when expectations were frozen. This is evidence of missing API
scope, not a behavioral mutant or a failed runtime test.

After implementation, direct builds at opt-level0 and3 each match every one of
the 4,726 frozen active-result/charge/suffix rows. All 12 old encode/fast tests,
two existing Reader tests and four new wrapper tests pass in each profile.
The Reader test also checks its unchanged 3,276-row corpus. A repeated optimized
recipe produces an identical own rlib; no target machine-code match is claimed.

| Compiled behavioral control | Mismatches / 4,726 rows | Compiled assertions |
| --- | ---: | --- |
| Roll back the limit failure's increment | 600 | Fail as expected |
| Always use the Reader on rejected markers | 392 | Fail as expected |
| Use inclusive fast threshold | 83 | Fail as expected |
| Charge after decoding | 755 | Fail as expected |

Every mutant library and driver compiled successfully before comparison. The
baseline missing-API compile failure is separate and is not counted above.

## Static evidence

Normal and optimized Python verification both pass 39 rejection controls and
produce identical JSON. Each verifier independently regenerates all fourteen
native/metadata files twice and requires exact equality with retained files.
All 1,374 bytes / 406 instruction rows agree between GNU and LLVM, without
normalization. The provider-selectable collector also regenerates exactly.

Controls cover eleven changed body/data bytes, four tables, three relocation
addends plus their symbol indexes, all six FDE lengths, five scalar-operand
counterfactuals, two malformed native exports, a missing independent export,
three pre-native identity failures and preservation of existing output. The
five scalar controls change charge, threshold, expected code, enabled mode or
overflow cutoff and change the separately calculated expectation. These are
byte-binding and mathematical controls, not captured execution.

## Actual environment and commands

Recorded host: macOS arm64; Python3.14.3; GNU objdump/readelf2.47.20260726;
Apple LLVM objdump21.0.0; pinned Rust1.94.1. `build-result.json` retains the
full compiler/linker identity, source/compiler hashes, exact direct recipes,
output hashes and actual exits. Direct builds use edition2024, warnings as
errors, overflow checks and one codegen unit. They invoke only the explicitly
selected compiler/linker and newly built Rust programs.

Ancestor `.cargo/config` / `.cargo/config.toml` files were checked before build;
none were present. The reviewed real component has no build.rs or dependencies,
uses the existing manifest/lockfile and has publish=false. No toolchain install,
dependency download, replacement workspace or captured-code helper was used.

```sh
python3 -B research/work-items/RE-005-bincode-wrapper-state-94/verify.py --gnu /opt/homebrew/opt/binutils/bin/objdump --llvm /Library/Developer/CommandLineTools/usr/bin/llvm-objdump --readelf /opt/homebrew/opt/binutils/bin/readelf
python3 -O -B research/work-items/RE-005-bincode-wrapper-state-94/verify.py
python3 -B research/work-items/RE-005-bincode-wrapper-state-94/build.py --rustc "$TOOLCHAIN/bin/rustc" --output "$NEW_OUTPUT" --controls
cargo test --offline --locked --manifest-path src/bincode-varint/Cargo.toml
cargo test --offline --locked --release --manifest-path src/bincode-varint/Cargo.toml
cargo clippy --offline --locked --manifest-path src/bincode-varint/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path src/bincode-varint/Cargo.toml --check
git diff --check -- src/bincode-varint research/work-items/RE-005-bincode-wrapper-state-94
```

Cargo commands used the explicit1.94.1 toolchain executables, RUSTC/RUSTDOC and
a separate scratch target directory. Debug/release Cargo tests, clippy and fmt
all exited0. Native flags can be overridden in `collect.py` and `verify.py`;
exact retained text remains provider/version-sensitive. The frozen
`evidence.py`, `corpus.py`, inputs and expectations were not amended to add
those flags. No failed semantic development run was discarded; the initial
direct run passed and the final source was rebuilt after doc-comment changes.

`validation/` retains compact static/build/baseline receipts, Cargo results,
test outputs and actual mutant assertion failures. Empty compiler logs and
duplicate optimized-verifier JSON are represented by their hashes rather
than copied twice. `MANIFEST.sha256` covers the packet files; `VALIDATION.json`
also records the changed component files. Full source compilation products
are scratch artifacts and are regenerated by the commands above.
