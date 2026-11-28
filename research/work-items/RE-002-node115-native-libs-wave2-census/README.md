# RE-002: node115 native C/C++/asm libraries compiled-byte census (Wave 2)

- Component ID: foundation (dependency-tagged `native-libraries` windows only; zero first-party credit)
- Target: node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Native toolchain: `GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`, GNU binutils `2.42-4ubuntu2.11` (Ubuntu 24.04 `noble-updates`), `rustc 1.95.0 (59807616e 2026-04-14)`
- Claim status: observation (static ELF parsing and clean-room crates.io C/C++/asm rebuilds; no target execution)

## Motivation

`RE-002-node115-vendor-census` previously matched 7,266 windows / 5,058,182 B of
statically linked native C/C++ libraries in node #115 `.text`, leaving ~2.0 MB
of native library code unmatched across `0x5d20000..0x63f0000`. Root-cause
forensics against node #115 `.rodata` and `.eh_frame` identified four causes:

1. **`tikv-jemalloc-sys 0.6.1`** (`5.3.0-1-ge13ca993e8ccb9ba9847cc330696e02839f328f7`)
   was previously built with default features (passing `--disable-stats` and
   omitting `--enable-prof`), whereas node #115 `.rodata` contains `prof_active`,
   `stats.arenas.0.nthreads`, `arenas.page`, and `background_thread.num_runs`
   (`features = ["stats", "profiling"]` with default `background_threads_runtime_support`).
   Additionally, `object_functions()` required `value == 0 && s[5] == size`,
   dropping multi-function `.pic.o` sections.
2. **`zstd-sys` and `lz4-sys`** previously resolved newer upstream C releases
   (`zstd 1.5.7` and `lz4 1.10.0`), whereas node #115 linked
   **`zstd-sys 2.0.13+zstd.1.5.6`** (`ZSTD_compressBlock_doubleFast` = 16,821 B)
   and **`lz4-sys 1.9.4`** (`LZ4HC_compress_generic_dictCtx` = 26,856 B).
3. **`blst 0.3.17`** needed `features = ["portable"]`, **`secp256k1-sys 0.10.0`
   and `0.11.0`** needed `features = ["recovery"]`, **`sha3-asm 0.1.9`**
   (`keccak-asm`) was unbuilt, and **`blake3 1.8.5`** x86-64 SIMD `.S` assembly
   (`SSE2`, `SSE4.1`, `AVX2`, `AVX-512`; 60,507 B in non-FDE gap
   `0x633a4d2..0x6349360`) used `STT_NOTYPE` entry labels ignored by
   `object_functions()`.
4. **`vendor_census.py`** rejected multi-copy native functions carrying psABI
   `gotpcrelx-mov-lea` / `gotpcrelx-call` relaxations, dropping COMDAT C++
   templates in `librocksdb-sys 0.11.0+8.1.1` and duplicate native bodies in
   `tikv-jemalloc-sys`, `zstd-sys`, `blst`, and `secp256k1-sys`.

Rebuilding the nine locked crates.io manifests under exact Ubuntu 24.04
`GCC 13.3.0-6ubuntu2~24.04.1` reproduces **1,714 strictly disjoint windows
(+1,262,053 B, +1.507% of node #115 `.text`)** across **8 native crates**,
bringing authenticated `native-libraries` coverage from 5,058,182 B to
**6,320,235 B** (+24.95%) once consolidated into `research/byte-windows.json`.

## Reproduce

1. Build the nine locked crates.io manifests in release mode with Ubuntu 24.04
   `GCC 13.3.0-6ubuntu2~24.04.1` (`CC`, `CXX`, `AR`, `RANLIB` pointing to the
   Ubuntu 24.04 toolchain) and `rustc 1.95.0`:
   - `jemalloc061-stats-prof` (`tikv-jemalloc-sys = "=0.6.1"`, `features = ["stats", "profiling"]`)
   - `zstd2013-156` (`zstd-sys = "=2.0.13+zstd.1.5.6"`, `features = ["legacy", "zdict_builder"]`)
   - `lz4-194` (`lz4-sys = "=1.9.4"`)
   - `rocksdb0210` (`rocksdb = "=0.21.0"`, `features = ["snappy", "lz4", "zstd", "zlib", "bzip2"]`)
   - `blake3-185` (`blake3 = "=1.8.5"`)
   - `blst0317-portable` (`blst = "=0.3.17"`, `features = ["portable"]`)
   - `secp256k1sys0100-rec` (`secp256k1-sys = "=0.10.0"`, `features = ["recovery"]`)
   - `secp256k1sys0110-rec` (`secp256k1-sys = "=0.11.0"`, `features = ["recovery"]`)
   - `keccak-asm019` (`keccak-asm = "=0.1.9"` -> `sha3-asm = 0.1.9`)

2. Verify the committed packet directly against `artifacts/node/115/hl-node`:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-native-libs-wave2-census/census.py --verify
(cd research/work-items/RE-002-node115-native-libs-wave2-census && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_native_libs_wave2_census_115 tests.test_node115_catalogue -v
```

## Method & Adversarial Gates

- **Native archives only**: only C/C++/asm `.a` archives are scanned; every
  record is tagged `native: true`, `dependency: "native-libraries"`,
  `component: "foundation"` (zero first-party credit).
- **Exact `tools/byte_progress.py` compatibility**: relocations are restricted
  strictly to four-byte `PC32` (2), `PLT32` (4), `GOTPCREL` (9), `GOTPCRELX`
  (41), and `REX_GOTPCRELX` (42), plus exact psABI `gotpcrelx-mov-lea` and
  `gotpcrelx-call` rewrites validated by `byte_progress.compare`.
- **Size and mask caps**: `length >= 32 B` (single-copy), `length >= 64 B`
  (multi-copy), unmasked bytes `>= 16`, relocation-masked bytes `<= length / 2`
  after relaxations.
- **Zero collision & strict multi-copy proof**:
  - Masked signatures must not collide with any `rustc 1.95.0` sysroot `*.rlib`
    function or span more than one native crate (`cross_crate_ambiguity = 1`
    rejected, `sysroot_std_collision = 0`).
  - For multi-copy matches (`copy_count > 1`), `length >= 64 B` and link-level
    `distinct_source_functions >= copy_count` are required (`STB_LOCAL` keyed by
    `(member, symbol)`, `STB_GLOBAL`/`STB_WEAK` keyed by `symbol` to respect LLD
    COMDAT merging; 1,064 `<64 B` copies and 28 unexplained multi-copy hits
    were rejected).
- **Boundaries & strict disjointness**:
  - All 1,703 C/C++ records match complete `.text` `.eh_frame` FDE extents.
  - All 11 `blake3` SIMD `.S` records (`60,507 B`, all 186 relocations
    `R_X86_64_PC32`, 0 non-relocation diffs) follow the existing
    `huf_decompress_amd64.S` assembly precedent using exact `.S` entry-label
    spans strictly inside node #115's non-FDE gap `0x633a4d2..0x6349360`.
  - Zero overlap with any existing window in `research/byte-windows.json`
    (excluding `node115-native-w2-*` once consolidated) and zero overlap with
    all sibling `research/work-items/*/{records.json,census.json}` packets.
- **Permissive licenses**: all 9 matched crate versions have verified permissive
  licenses in `licenses.json`.

## Results

**1,714 windows (1,703 FDEs + 11 `blake3` `.S` asm), 1,262,053 bytes**, 100.00%
relocation-qualified, **172 raw-equal windows**, across **8 native crates**:

| Crate | Version / Features | Windows | Bytes | Single-copy | Multi-copy (`>=64 B`) | Raw-equal | VA Range |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| `tikv-jemalloc-sys` | `0.6.1+5.3.0-1-ge13ca99...` (`stats, profiling`) | 619 | 421,181 | 517 | 102 | 7 | `0x63493c0..0x63efd19` |
| `zstd-sys` | `2.0.13+zstd.1.5.6` (`legacy, zdict_builder`) | 106 | 346,653 | 68 | 38 | 12 | `0x620dfb0..0x62db1b0` |
| `librocksdb-sys` | `0.11.0+8.1.1` (`snappy, lz4, zstd, zlib, bzip2`) | 820 | 262,744 | 1 | 819 | 44 | `0x5d2e540..0x6205556` |
| `lz4-sys` | `1.9.4` | 13 | 112,816 | 13 | 0 | 0 | `0x62e5080..0x6300c03` |
| `blake3` | `1.8.5` (SSE2, SSE4.1, AVX2, AVX-512 `.S`) | 11 | 60,507 | 11 | 0 | 0 | `0x633a680..0x634935a` |
| `blst` | `0.3.17` (`portable`) | 127 | 44,880 | 115 | 12 | 106 | `0x5d21240..0x5d2c9f9` |
| `secp256k1-sys` | `0.10.0` + `0.11.0` (`recovery`) | 14 | 12,075 | 2 | 12 | 0 | `0x63217a0..0x6339e90` |
| `sha3-asm` | `0.1.9` (`keccak-asm`) | 4 | 1,197 | 4 | 0 | 3 | `0x633a000..0x633a4d2` |
| **Total** | **8 native libraries** | **1,714** | **1,262,053** | **731** | **983** | **172** | `0x5d21240..0x63efd19` |

## Limitations & Follow-Up Finding (TLS Linker Relaxations)

- All windows are dependency-tagged (`native-libraries`) under `foundation` and
  award zero first-party component credit; no `research/progress.json` gates are
  changed.
- `research/byte-windows.json` is intentionally left unmodified in this packet so
  consolidation waves fold `node115-native-w2-0001..1714` cleanly without merge
  conflicts.
- **Residual native TLS code (~736 KB intentionally excluded here)**: static
  forensics showed that nearly all remaining unmatched native bytes in
  `0x5d20000..0x63f0000` are exact-length Ubuntu GCC 13.3.0 functions differing
  solely at standard x86-64 ELF TLS linker relaxation sites currently outside
  `tools/byte_progress.py`'s `{2, 4, 9, 41, 42}` allowlist:
  - **`R_X86_64_TLSGD` (kind 19, GD->LE rewrite)** in `librocksdb-sys` (~600 KB,
    e.g. `rocksdb::DBImpl::PromoteL0` 13,707 B, `MergeHelper::MergeUntil`
    13,366 B, `FlushJob::Run` 10,958 B, `BlockFetcher::ReadBlockContents`
    10,602 B — 0 non-TLS diffs across all 4 functions).
  - **`R_X86_64_GOTTPOFF` (kind 22, IE->LE rewrite)** in `tikv-jemalloc-sys`
    (~136 KB, e.g. `stats_arena_print` 18,529 B, `_rjem_mallocx` 12,182 B,
    `stats_arena_bins_print` 12,133 B, `do_rallocx` 11,598 B,
    `stats_general_print` 8,046 B, `_rjem_realloc` 7,975 B, `_rjem_calloc`
    7,906 B, `_rjem_je_malloc_default` 7,611 B).
  These remain excluded unless `tools/byte_progress.py` is explicitly extended to
  support named x86-64 psABI TLS relaxations in a future wave.
