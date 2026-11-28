# RE-004: Node #115 Stream E1 (`orderbook`, `assets`) Pure Business-Logic Compiled-Byte Matches

## Target
- Binary: `artifacts/node/115/hl-node` (`105,896,032` bytes)
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Compiler profile: `rustc +1.95.0 --edition=2021 -C opt-level=3 -C overflow-checks=yes -C lto=thin`
  - `main.rs`: pure `std`, `#![forbid(unsafe_code)]`, 0 external dependencies (13 FDEs / `3,537` B)
  - `jem/`: locked offline `tikv-jemallocator = "=0.6.0"`, `#![forbid(unsafe_code)]` (3 FDEs / `618` B)

## Summary
- **16 strictly disjoint, 100.00% relocation-qualified (`0` non-relocation diffs), pure first-party business-logic `.text` FDEs = `4,155` bytes** (zero `Debug`/`Visitor`/stdlib attribution; zero overlap with `research/byte-windows.json` or any sibling compiled-byte packet across all VA key spellings):
  - **`orderbook`** (`6` FDEs / `1,998` B):
    - `Books::cancel_spot_orders_for_user` (`0x22f2160`, `0x50d7ca0`, `0x50d7de0` — `3 x 318` B = `954` B; `l1/src/books.rs:19:47`)
    - `Books::cancel_perp_orders_for_user` (`0x22f2000`, `0x50d7b40`, `0x50d7f20` — `3 x 348` B = `1,044` B; `l1/src/books.rs:19:47`)
  - **`assets`** (`10` FDEs / `2,157` B):
    - `SpotMeta::sz_from_wire` (`0x29aea00`, `0x593da30` — `2 x 242` B = `484` B; `l1/src/spot_meta.rs:119:33`)
    - `PerpMeta::px_from_wire` (`0x593d920` — `272` B; `l1/src/perp_meta.rs:287:28`)
    - `qtys::scale_one_minus_frac` (`0x2bde660`, `0x54a70a0` — `2 x 179` B = `358` B; `l1/src/qtys/mod.rs:847:1`)
    - `SpotMeta::usdc_wei_per_base_sz` (`0x3c49360` — `211` B; `l1/src/spot_meta.rs:1055:9`)
    - `SpotMeta::pair_unique_quote_tokens` (`0x46dfab0` — `214` B; `l1/src/spot_meta.rs:119:33`)
    - `SpotMeta::set_full_name` (`0x2c54190`, `0x55c5da0`, `0x55c5e70` — `3 x 206` B = `618` B; `.rodata` `"full name already set"`)

## Verification
```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-004-node115-stream-e1-orderbook-assets-logic-byte-matches/verify.py --self-test
(cd research/work-items/RE-004-node115-stream-e1-orderbook-assets-logic-byte-matches && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_stream_e1_orderbook_assets_logic_byte_matches_115 -v
```
