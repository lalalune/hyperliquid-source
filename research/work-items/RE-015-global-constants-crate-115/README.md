# RE-015: node #115 `global_constants` complete codegen-unit map and Rust crate integration

This packet binds the complete `global_constants` codegen unit (`0x1772f80..0x1778ad7`, 40 FDEs plus adjacent `Chain::fmt` at `0x1778c60..0x1778cca`), all five panic `Location` records referencing `global_constants/src/aws_name.rs` and `global_constants/src/static_config.rs`, all GOT/data exports (`0x64e23e0..0x64e2418` and `0x64e0918 -> 0x64f06c0`), all 79 `AwsName` discriminants (`0x63f8788` / `0x6410ce8`), the `.rodata` `0x4671d0` 79-entry `f64` lookup table, and the integrated `src/global-constants` Rust crate (joining `node115-chain-name-codec` and `node115-spot-mark-codec`) to Linux x86-64 node #115.

- Component ID: `constants` (`global_constants/*`); task `RE-015`.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (`artifacts/node/115/hl-node`).
- Claim status:
  - **Observation**: ELF section bounds, all 41 FDE start/end extents and body SHA-256 digests, all 5 `R_X86_64_RELATIVE` panic `Location` records (`file`, `line`, `col`), all 8 GOT/data relocation targets, both 79-entry `AwsName` pointer/length arrays (`0x63f8788`, `0x6410ce8`), the 79-entry `f64` table at `0x4671d0`, and `Chain::fmt` string references at `0x1778c60`.
  - **Inference**: Rust source roles (`AwsName`, `StaticConfig`, `STATIC_CONFIG`, `VariantNotFound`, `ChainDisplay`) and the inlined predicate semantics of `0x4671d0` and `0x10078c000`.
  - **Unresolved**: Full `getpwuid_r` fallback path inside `0x17782e0` when `$HOME` is empty/unset, `LazyLock` poisoning/concurrency internals, exact caller meaning of `aws_name.rs:213:29` (`unimplemented!()` inlined at `0x2e13a1a`/`0x2e13a38`), and whole-crate byte-identity comparison against `rustc 1.95.0` codegen.
- Captured code executed: `false`. All verification is static binary parsing + independently authored Rust unit tests.
- Progress gate: no automatic gate flip claimed in this packet; `identity` remains unmeasured.

## Key node #115 observations

1. **Complete `global_constants` panic `Location` census (5 total across the entire binary)**:
   - `global_constants/src/aws_name.rs:213:29` (`0x6411208`) — `panic!("not implemented")` inlined at `0x2e13a24`, `0x2e13a3f`.
   - `global_constants/src/aws_name.rs:295:44` (`0x64111d8`) — `read_to_string().unwrap()` in `0x1773fd0` (`0x1774079`).
   - `global_constants/src/aws_name.rs:295:68` (`0x64111f0`) — `from_str().unwrap()` in `0x1773fd0` (`0x17740a0`).
   - `global_constants/src/static_config.rs:61:17` (`0x6411420`) — `"could not create {}: {}"` in `0x1778270` (`0x17782a8`).
   - `global_constants/src/static_config.rs:24:9` (`0x6411438`) — `"cham_dir does not exist: {}"` in `0x17785f0` (`0x1778708`).
2. **All GOT/data entrypoints of `global_constants`**:
   - `0x64f06c0 -> 0x17785f0` (`STATIC_CONFIG` `LazyLock<StaticConfig>` initializer, reached via GOT `0x64e0918`, 213 `.text` references).
   - `0x64e23e0 -> 0x1772fa0` (`aws_name_path`), `0x64e23e8 -> 0x17782e0` (`home_dir`), `0x64e23f0 -> 0x17780c0` (`resolve_cham_dir`), `0x64e23f8 -> 0x1773fd0` (`AwsName::read_from_file`), `0x64e2400 -> 0x1775500` (`AwsName::from_str`), `0x64e2408 -> 0x1774e60` (`AwsName::fmt`), `0x64e2418 -> 0x17783e0` (`read_aws_name`).
3. **`StaticConfig` JSON schema (`0x17771b0`)**:
   - Single field `"aws_name"` (`0x458fb8`), duplicate field rejected (`0x43351a`), unknown fields skipped (`0x1776910`), missing field or empty sequence `[]` invokes `0x1773fd0`, value accepts quoted string or `{"Variant": null}` unit-variant map (`0x1773070`), trailing check enforces mask `0x100002600` (`\t`, `\n`, `\r`, `' '`).
4. **Integrated Rust crate (`src/global-constants`)**:
   - Joins `node115-chain-name-codec` and `node115-spot-mark-codec` with `AwsName` and `StaticConfig` in pure Rust (`rustc 1.95.0`, zero crates.io dependencies).

## Reproduce

```sh
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/evm-bridge-api \
  cargo test --manifest-path src/global-constants/Cargo.toml
python3 -m unittest tests.test_global_constants_115 -v
python3 tools/verify_packets.py
```
