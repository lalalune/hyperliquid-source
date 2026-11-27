# RE-015: Node #115 `constants` (`global_constants`) Full-Scope Gate Closure & Compiled-Byte Matches

- **Component ID**: `constants` (Stream F, `RE-015`, resolving #205 / #206 / #241)
- **Target Artifact**: `artifacts/node/115/hl-node` (Linux x86-64 ELF, 105,896,032 bytes)
- **Target SHA-256**: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Toolchain**: `rustc 1.95.0 (59807616e 2026-04-14)` (`--edition=2021 --crate-type=rlib -C opt-level=3 -C overflow-checks=yes`)
- **Claim Status**: Every FDE extent, `.rodata`/`.data.rel.ro`/`.rela.dyn` target, instruction byte sequence, and compiled-byte comparison is statically verified against the authenticated node #115 ELF (never executed). No acceptance gate in `research/progress.json` is flipped directly by this packet; this packet provides the verified evidence for joint `@coordinator` / `@deps-forks` / `@pr-scout` gate review.

## Closures of #205 / #206 / #241 Blockers

### 1. `global_constants/src/aws_name.rs:213:29` Resolved

- `.data.rel.ro` panic `Location` `0x6411208` (`global_constants/src/aws_name.rs:213:29`) has **exactly 2 references** across `.text`, both inside `0x2e11b00..0x2e13c3a` (validator-pair disconnect monitor, `"found disconnected validator pairs "` at `.rodata` `0x616fb5`, called by `0x2af77f0` at `0x2af877d`):
  - `0x2e12c68` (`cmp byte ptr [r14 + 0xbd5], 0`) -> `je 0x2e13a38` (`lea rdi, [0x481f69]` `"not implemented"`, `lea rdx, [0x6411208]` at `0x2e13a3f`)
  - `0x2e12fde` (`cmp byte ptr [r14 + 0xbd5], 0`) -> `je 0x2e13a1a` (`lea rdi, [0x481f69]` `"not implemented"`, `lea rdx, [0x6411208]` at `0x2e13a24`)
- Both sites initialize `STATIC_CONFIG` (`0x64f06c0` via `0x64e0918`, `Once` at `+0x50`), then check `Chain` at `+0xbd5` (`0 = Local`, `1 = Sandbox`, `2 = Testnet`, `3 = Mainnet`) and panic with `unimplemented!()` iff `chain == Chain::Local`.
- Implemented in `src/global-constants/src/aws_name.rs` as `AwsName::assert_non_local_chain(chain)` with tests covering all 4 `ChainName` variants.

### 2. `$HOME`-Unset `getpwuid_r` Fallback & `LazyLock` Concurrency/Poisoning

- Disassembly of `0x17782e0..0x17783dd` (`global_constants::static_config::home_dir`, 253 B) proves it calls Rust 1.95.0 stdlib `std::env::home_dir` (`0x5c9abb0`, via GOT slot `0x64e2410`), which loads `"HOME"` (`0x454d4f48`) and on Unix falls back to `sysconf(_SC_GETPW_R_SIZE_MAX = 0x46)` + `getpwuid_r` when `$HOME` is unset/empty, then validates UTF-8 (`0x16815e0`) and returns `String::new()` on `None`.
- `src/global-constants/src/static_config.rs::home_dir()` calls `std::env::home_dir()` directly (`#![forbid(unsafe_code)]`, 0 external deps), tested with `$HOME` unset in an isolated child process (`tests/test_constants_gate_closure_115.py`), alongside multi-threaded `LazyLock` single-init, `LazyLock` panic-poisoning, blocked `hl` creation (`0x1778270`), and invalid `/aws_name` parse panic (`0x1774092`) boundary tests.

### 3. `.rodata` & `.data.rel.ro` Tables Authenticated

- `.rodata` `0x4671d0`: all 79 `f64` values verified (exact 18 indices `[1, 2, 9, 10, 11, 12, 13, 15, 16, 18, 20, 22, 25, 26, 35, 36, 37, 38]` equal `1.0`, remaining 61 equal `5.0`).
- `.data.rel.ro` `0x63f8788` and `0x6410ce8`: both 79-entry `(&str)` pointer/length tables resolved via `.rela.dyn` and verified against `AwsName::ALL` (`0..=78`).

### 4. Complete 40+1-FDE CGU Inventory & 12 New Compiled-Byte Matches (`5,031 B`)

All **40 FDEs** of the `global_constants` CGU (`0x1772f80..0x1778ad7`, `23,050 B`) plus adjacent `Chain::fmt` (`0x1778c60..0x1778cca`, `106 B`) are classified in `records.json`. In addition to `0x1774100` (`2,785 B` in `research/byte-windows.json`) and `0x17785d0` + `0x1778c60` (`131 B` in `RE-015-node115-stream-f-byte-matches`), `lib.rs` live-compiles **12 brand-new, zero-overlap, 100.00% relocation-qualified CGU FDEs (`5,031 B` total, `4,305/5,031 = 85.57%` raw-equal, 0 non-relocation mismatches)** — covering **100% of all non-jemalloc, non-`serde_json` FDEs** in the CGU (`14/40 FDEs = 7,841 / 23,050 B = 34.02%` total CGU bytes matched):

| Role | FDE Range | Bytes | Raw-Equal | Reloc-Qualified |
|---|---|---:|---:|:---:|
| `AwsName::from_str` | `0x1775500..0x1775dc6` | 2,246 B | 2,242 / 2,246 (99.82%) | Yes |
| `AwsName::fmt` (`Display`) | `0x1774e60..0x17754f1` | 1,681 B | 1,045 / 1,681 | Yes |
| `str::trim` (Unicode whitespace) | `0x1778840..0x1778ad7` | 663 B | 655 / 663 (98.79%) | Yes |
| `cham_dir` `create_dir_all` panic | `0x1778270..0x17782d7` | 103 B | 73 / 103 | Yes |
| `LazyLock<StaticConfig>` `Once::call_once_force` | `0x1774bf0..0x1774c56` | 102 B | 90 / 102 | Yes |
| `LazyLock<StaticConfig>` `FnOnce::call_once` shim | `0x1774c80..0x1774ce6` | 102 B | 90 / 102 | Yes |
| `Visitor::expecting("variant identifier")` | `0x1774c60..0x1774c79` | 25 B | 21 / 25 | Yes |
| `Visitor::expecting("VariantNotFound")` | `0x1774e40..0x1774e59` | 25 B | 21 / 25 | Yes |
| `Visitor::expecting("unit")` | `0x17785b0..0x17785c9` | 25 B | 21 / 25 | Yes |
| `<String as Display>::fmt` (`f.pad` thunk #1) | `0x1772f80..0x1772f94` | 20 B | 16 / 20 | Yes |
| `<String as Display>::fmt` (`f.pad` thunk #2) | `0x1777fb0..0x1777fc4` | 20 B | 16 / 20 | Yes |
| `<&str as Display>::fmt` thunk | `0x1778590..0x17785a3` | 19 B | 15 / 19 | Yes |
| **Total (12 new CGU FDEs)** | | **5,031 B** | **4,305 / 5,031 (85.57%)** | **12 / 12** |

### Exact Classification of the Remaining 26 CGU FDEs

- **16 monomorphized `serde_json` / `serde` helpers** (`0x1773070`, `0x1775dd0..0x1777faf`, `0x1777fd0`): generated from vendored `serde` + `serde_json` crate code.
- **4 `drop_in_place` routines** (`0x1774cf0`, `0x1774dd0`, `0x1778060`, `0x1778770`): inline `tikv-jemallocator` `sdallocx` (`callq *0x64df4a0(%rip) -> 0x635de30`) with BMI1 `tzcntq`.
- **6 `std::fs`/`std::env`/`format!` wrappers** (`0x1772fa0` `aws_name_path`, `0x1773fd0` `read_aws_name_fallback`, `0x17780c0` `cham_dir`, `0x17782e0` `home_dir`, `0x17783e0` `read_aws_name`, `0x17785f0` `StaticConfig::new`): every `String` drop inlines `tikv-jemallocator` `sdallocx(ptr, size, flags=0)` (`xorl %edx, %edx; callq *0x64df4a0(%rip)`), differing by 3 bytes per drop from stdlib `__rust_dealloc(ptr, size, align=1)`.

## Reproduce

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-015-node115-constants-gate-closure/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_constants_gate_closure_115 tests.test_global_constants_115 -v
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 cargo test --offline --locked --manifest-path src/global-constants/Cargo.toml
CARGO_BUILD_JOBS=4 cargo clippy --offline --locked --manifest-path src/global-constants/Cargo.toml --all-targets -- -D warnings
(cd research/work-items/RE-015-node115-constants-gate-closure && sha256sum -c MANIFEST.sha256)
```
