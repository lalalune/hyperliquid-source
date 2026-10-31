# Hyperliquidity Evidence Packet (Node #94)

Static verification evidence packet for `l1/src/hyperliquidity.rs` extracted from `artifacts/node/94/hl-node`
(SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`). Zero binary execution; offline ELF analysis only.

## Subsystem Extents
Total verified routine footprint: **3 FDEs**, **2,704 bytes**.

| Routine | Start | End | Size | SHA-256 |
|---|---|---|---|---|
| `register_hyperliquidity` | `0x3261c40` | `0x3262590` | 2384 B | `62057313067d39bec3ac6723f1e27005a4e04ce51d8a04875f7bd15719f49d9f` |
| `hyperliquidity_cleanup_helper` | `0x3262590` | `0x3262600` | 112 B | `a7e97c09dcf960ced36da93358684200ef653a18020124920fbda473161f76aa` |
| `market_cap_in_scaled_range` | `0x3262600` | `0x32626d0` | 208 B | `87ce00650bbeaf876b6b19fa153bd8b8ce37cbbeda9e4b3c46f6df092507ef3a` |

## Panic Records
- `0x56df860`: `/home/ubuntu/hl/code_Mainnet/l1/src/hyperliquidity.rs:355:29` (referenced at `0x3262531`)

## Key Constants & Limits
- `HYPERLIQUIDITY_PRICE_RATIO`: `1.003` (double at `0x20a838`)
- `MIN_HYPERLIQUIDITY_ORDERS`: `10` (`0xa` at `0x3261eef`)
- `MAX_RAW_HYPERLIQUIDITY_VALUE`: `0x1999999999999999` (at `0x32620d7`)
- `MIN_END_MARKET_CAP_USDC`: `1,000,000,000` (`0x3b9aca00` at `0x326225d`)
- `MAX_END_MARKET_CAP_USDC`: `100,000,000,000` (`0x174876e800` at `0x3262266`)
- `MAX_START_MARKET_CAP_USDC`: `10,000,000` (`0x989680` at `0x326228c`)
- `MARKET_CAP_LOWER_SCALE`: `70,000,000` (`0xaae60 * 100` at `0x3262606`)
- `MARKET_CAP_UPPER_SCALE`: `130,000,000` (`0x13d620 * 100` at `0x326262a`)

## Status Codes Ground Truth
- `SUCCESS_CODE = 390` (`0x186` at `0x3261fb1`)
- `ERR_STATUS = 223` (`0xdf` at `0x3261d46`)
