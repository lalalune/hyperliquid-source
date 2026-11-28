# RE-002: node115 native C/C++ libraries TLS-relaxed compiled-byte census (Wave 3)

- Component ID: foundation (dependency-tagged `native-libraries` windows only; zero first-party credit)
- Target: node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Native toolchain: `GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`, GNU binutils `2.42-4ubuntu2.11` (Ubuntu 24.04 `noble-updates`), `rustc 1.95.0 (59807616e 2026-04-14)`
- Claim status: observation (static ELF parsing and clean-room crates.io C/C++ rebuilds; no target execution)

## Motivation

`RE-002-node115-native-libs-wave2-census` (`4483a7ec8`, +1,262,053 B) exhausted
>99% of all non-TLS statically linked native code in node #115 `.text`. Full-binary
forensic auditing of the remaining unmatched `endbr64` FDEs across `0x5d00000..0x6400000`
showed that **735,619 B across 362 complete `.text` FDEs** (`librocksdb-sys 0.11.0+8.1.1`
and `tikv-jemalloc-sys 0.6.1 [stats, profiling]`) compiled byte-for-byte identically
under Ubuntu 24.04 `GCC 13.3.0-6ubuntu2~24.04.1` and differed solely at standard
x86-64 ELF psABI TLS linker relaxation sites (Ulrich Drepper, *ELF Handling For
Thread-Local Storage*, §4.2.4–4.2.5) emitted by LLD 22.1.2:

1. **`tlsgd-gd-le`** (`R_X86_64_TLSGD`, kind `19`, paired with `R_X86_64_PLT32`
   `__tls_get_addr` at `offset + 8`):
   - Source `.o` (16 B): `66 48 8d 3d [disp32] 66 66 48 e8 [plt32]`
   - Linked target (16 B): `64 48 8b 04 25 00 00 00 00 48 8d 80 [tpoff32]`
   - Appears at **1,339 sites** in `librocksdb-sys` (e.g. `rocksdb::perf_context` /
     `iostats_context` `thread_local` timers inside `BuildTable`, `MultiGet`,
     `PromoteL0`, `MergeUntil`, `FlushJob::Run`, `ReadBlockContents`).
2. **`tlsgd-gd-ie`** (`R_X86_64_TLSGD`, kind `19`, paired with `R_X86_64_PLT32`
   `__tls_get_addr` at `offset + 8`):
   - Source `.o` (16 B): `66 48 8d 3d [disp32] 66 66 48 e8 [plt32]`
   - Linked target (16 B): `64 48 8b 04 25 00 00 00 00 48 03 05 [gottpoff32]`
   - Appears at **130 sites** in `librocksdb-sys` (dynamic shared-object TLS
     variables such as `std::__once_callable` in `libstdc++.so.6`).
3. **`gottpoff-ie-le`** (`R_X86_64_GOTTPOFF`, kind `22`):
   - Register-preserving 3-byte prefix/opcode/ModRM rewrites before `[tpoff32]`:
     - `mov reg, [rip+disp32]` (`48/4c 8b ModRM(00,reg,101)`) ->
       `mov reg, imm32` (`48/49 c7 ModRM(11,000,reg)`)
     - `add reg, [rip+disp32]` (`48/4c 03 ModRM(00,reg,101)`) ->
       `lea reg, [reg+disp32]` (`48/4d 8d ModRM(10,reg,reg)`) or
       `add reg, imm32` (`48/49 81 ModRM(11,000,reg)`)
   - Appears at **119 sites** in `tikv-jemalloc-sys` (initial-exec `tsd_tls` in
     `stats_arena_print`, `_rjem_mallocx`, `stats_arena_bins_print`, `do_rallocx`,
     `stats_general_print`, `_rjem_realloc`, `_rjem_calloc`, `_rjem_je_malloc_default`).

Extending `tools/byte_progress.py` with exact, register-preserving, zero-wildcard
validators for those three psABI templates unlocks **362 strictly disjoint complete
`.text` FDEs (+735,619 B, +0.879% of node #115 `.text`)**, raising total
authenticated `native-libraries` coverage (Wave 1 + Wave 2 + Wave 3) to
**7,055,854 B** (>99% of all statically linked native library code in node #115).

## Reproduce

1. Build the two locked crates.io manifests in release mode under Ubuntu 24.04
   `GCC 13.3.0-6ubuntu2~24.04.1` and `rustc 1.95.0`:
   - `rocksdb0210` (`rocksdb = "=0.21.0"`, `features = ["snappy", "lz4", "zstd", "zlib", "bzip2"]`)
   - `jemalloc061-stats-prof` (`tikv-jemalloc-sys = "=0.6.1"`, `features = ["stats", "profiling"]`)
2. Verify the committed packet directly against `artifacts/node/115/hl-node`:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-native-libs-wave3-tls-census/census.py --verify
(cd research/work-items/RE-002-node115-native-libs-wave3-tls-census && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_node115_catalogue tests.test_native_libs_wave2_census_115 tests.test_native_libs_wave3_tls_census_115 -v
```

## Method & Adversarial Gates

- **Exact psABI TLS templates only**: `tools/byte_progress.py` accepts `kind == 19`
  ONLY with `'relaxation' in ('tlsgd-gd-le', 'tlsgd-gd-ie')` and a paired `kind == 4`
  (`PLT32`) relocation at `offset + 8`, and accepts `kind == 22` ONLY with
  `'relaxation' == 'gottpoff-ie-le'` preserving exact destination register bits.
  Untagged kind-19/kind-22 sites, mode swaps, dropped `PLT32` pairs, and wrong
  registers raise `ValueError`.
- **Complete FDEs, size/mask caps & zero overlaps**:
  - All 362 records are complete `.text` `.eh_frame` FDEs (`342` single-copy,
    `20` multi-copy `>= 64 B` with link-level `distinct_source_functions >= copy_count`).
  - `unmasked_bytes >= 16`, `relocation_bytes * 2 <= length`, zero sysroot `std`
    collisions, zero cross-crate ambiguity, zero overlaps with
    `research/byte-windows.json` (consolidation-safe prefix `node115-native-w3-tls-*`)
    or any sibling packet including `RE-002-node115-native-libs-wave2-census`.
- **Permissive licenses**: both crates have verified permissive licenses in
  `licenses.json`.

## Results

**362 complete `.text` FDEs, 735,619 bytes**, 100.00% relocation-qualified across
**2 native crates** (`1,588` verified psABI TLS relaxation sites):

| Crate | Version / Features | FDEs | Bytes | Single-copy | Multi-copy (`>=64 B`) | TLS Relaxation Sites | VA Range |
| --- | --- | ---: | ---: | ---: | ---: | --- | --- |
| `librocksdb-sys` | `0.11.0+8.1.1` (`snappy, lz4, zstd, zlib, bzip2`) | 308 | 599,910 | 290 | 18 | 1,339 `tlsgd-gd-le`, 130 `tlsgd-gd-ie` | `0x5d42ea0..0x6202e78` |
| `tikv-jemalloc-sys` | `0.6.1+5.3.0-1-ge13ca99...` (`stats, profiling`) | 54 | 135,709 | 52 | 2 | 119 `gottpoff-ie-le` | `0x634f0b0..0x63efcbc` |
| **Total** | **2 native libraries** | **362** | **735,619** | **342** | **20** | **1,588 verified psABI TLS sites** | `0x5d42ea0..0x63efcbc` |

Top matched FDEs include:
- `librocksdb-sys`: `rocksdb::BuildTable` (`0x5e1b9c0`, 19,137 B), `rocksdb::BlockBasedTable::MultiGet` (`0x611a4e0`, 16,049 B), `rocksdb::DBImpl::PromoteL0` (`0x5e46100`, 13,707 B), `rocksdb::MergeHelper::MergeUntil` (`0x5f1b550`, 13,366 B), `rocksdb::FlushJob::Run` (`0x5ed5df0`, 10,958 B), `rocksdb::BlockFetcher::ReadBlockContents` (`0x61572d0`, 10,602 B).
- `tikv-jemalloc-sys`: `stats_arena_print` (`0x63e3578`, 18,529 B), `_rjem_mallocx` (`0x63577f0`, 12,182 B), `stats_arena_bins_print` (`0x63de5bd`, 12,133 B), `do_rallocx` (`0x6350210`, 11,598 B), `stats_general_print` (`0x63e160a`, 8,046 B), `_rjem_realloc` (`0x635a7a0`, 7,975 B), `_rjem_calloc` (`0x6355900`, 7,906 B), `_rjem_je_malloc_default` (`0x6353a70`, 7,611 B).

## Limitations

- Dependency-tagged (`native-libraries`) under `foundation` only; awards zero
  first-party component credit and flips zero gates in `research/progress.json`.
- `research/byte-windows.json` is left untouched so consolidation waves fold
  `node115-native-w3-tls-0001..0362` cleanly alongside Wave 2.
- Relocation displacements are masked, not resolved.
