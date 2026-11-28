# RE-004: Node #115 Stream E1 Fees, Orderbook & Assets Wave-2 Business-Logic Compiled-Byte Matches

## Target

- Binary: `artifacts/node/115/hl-node` (`105,896,032` bytes)
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Compiler: `rustc +1.95.0 --edition=2021 -C opt-level=3 -C overflow-checks=yes -C lto=thin`
- Scope: **9 strictly disjoint, 100% pure first-party business-logic `.text` FDEs (`2,483 B`, `2,160/2,483 = 86.99%` raw-equal, `0` non-relocation diffs)** spanning `fees`, `orderbook`, `assets`, and `risk` (`SpotClearinghouse`), built with `#![forbid(unsafe_code)]` and **zero external crate dependencies**.

## Method

- `stubs.rs` (`--crate-type=rlib -C opt-level=3`) provides safe cross-crate call targets (`bug_log`, `fetch_mid_raw`, `spot_mark_px`, `wei_to_usdc_ntl`) and `OuterDiff2c8`/`OuterDiff2b8` book-diff enums with `force_push_2c8`/`force_push_2b8`, so `rustc` emits exact `R_X86_64_REX_GOTPCRELX` (`ff 15`) indirect calls for cross-crate helpers and `RawVec::grow_one` while keeping local `drop_in_place` calls as 5-byte `e8` rel32 under `-C relocation-model=pie`.
- `lib_pic.rs` (`--crate-type=lib -C opt-level=3 -C overflow-checks=yes -C lto=thin --emit=obj`) compiles 7 FDEs across `fees`, `assets`, and `risk`.
- `lib_pie.rs` (`--crate-type=lib -C relocation-model=pie -C opt-level=3 -C overflow-checks=yes -C lto=thin --emit=obj`) compiles the 2 `Level::modify_order_sz` (`orderbook`) FDEs (Perp `0x2c8` B and Spot `0x2b8` B diff records).
- Every window is verified with `tools/byte_progress.py::compare` (strict ELF relocation kind & addend validation from `SHT_RELA`), checked against `work/index/node-115-fde.tsv` for exact FDE extent, anchored via `.rela.dyn` -> `.data.rel.ro` `core::panic::Location` records in node #115, checked for zero overlaps internally, against `research/byte-windows.json` (consolidation-safe), and against all sibling compiled-byte packets, and guarded by 4 negative controls.

## Matched FDEs

| Component | Label | Start VA | End VA | Size | Pool | Anchor |
| --- | --- | --- | --- | ---: | --- | --- |
| `fees` | `FeeTracker::subaccounts_vlm_sum` | `0x294bcd0` | `0x294bd73` | 163 B | `pic_lib` | `l1/src/qtys/impl_ntl.rs:682:1` |
| `orderbook` | `Level::modify_order_sz (spot)` | `0x5192060` | `0x519223f` | 479 B | `pie_lib` | `l1/src/book/level.rs:32:54` |
| `orderbook` | `Level::modify_order_sz (perp)` | `0x5192240` | `0x519241f` | 479 B | `pie_lib` | `l1/src/book/level.rs:32:54` |
| `assets` | `SpotMeta::mid_px_to_f64` | `0x2cac7d0` | `0x2cac8bf` | 239 B | `pic_lib` | `l1/src/spot_meta.rs:1055:9` |
| `assets` | `SpotMeta::mid_px_to_f64` | `0x56449a0` | `0x5644a8f` | 239 B | `pic_lib` | `l1/src/spot_meta.rs:1055:9` |
| `assets` | `SpotMeta::mid_px_to_f64` | `0x5644a90` | `0x5644b7f` | 239 B | `pic_lib` | `l1/src/spot_meta.rs:1055:9` |
| `assets` | `SpotMeta::is_user_frozen` | `0x3c49440` | `0x3c4953f` | 255 B | `pic_lib` | `l1/src/spot_meta.rs:119:33` |
| `assets` | `qtys::net_balance` | `0x4215880` | `0x421593e` | 190 B | `pic_lib` | `l1/src/qtys/mod.rs:847:1` |
| `risk` | `SpotClearinghouse::capped_usdc_ntl` | `0x3bfa270` | `0x3bfa338` | 200 B | `pic_lib` | `l1/src/spot_meta.rs:119:33` |

Totals: **`9` FDEs = `2,483 B`** (`fees`: 1w / 163 B; `orderbook`: 2w / 958 B; `assets`: 5w / 1,162 B; `risk`: 1w / 200 B).

## Reproduction

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-004-node115-stream-e1-fees-book-logic-wave2-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_stream_e1_fees_book_logic_wave2_byte_matches_115 -v
```
