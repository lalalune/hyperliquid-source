# RE-015 · delegator summary JSON in node #115

The serializer at `0x2ed8270` writes three amounts as quoted decimal strings and the withdrawal count as an unsigned JSON number. The initial format uses ten decimal places. Trailing zeros are removed while keeping the final `.0`, and rounded negative zero is written as `0.0`. For example, binary64 `1.23456789016` becomes `"1.2345678902"`. The public `info_api::response::DelegatorSummary::write_json` implements this response for supplied values.

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source base: `2da45cb0a761cff6b478e40421699857d87a94df`.

| JSON key | Input byte offset | Literal VA | Key reference | Value writer call |
| --- | ---: | --- | --- | --- |
| delegated | 0 | 0x641d6b | 0x2ed82a7 | 0x2ed82bb |
| undelegated | 8 | 0x641d74 | 0x2ed82d8 | 0x2ed82e9 |
| totalPendingWithdrawal | 16 | 0x641d7f | 0x2ed8302 | 0x2ed8313 |
| nPendingWithdrawals | 24 | 0x641d95 | 0x2ed8328 | 0x2ed833c |

The first three calls target `0x2ebfd30`, which tail-jumps to `0x2edf980`. That routine loads binary64, calls the relocated helper at `0x44a61d0`, and writes its byte slice between two quote bytes. The count path through `0x2ebf720` loads a qword into the integer writer's value register and calls `0x2eac1f0` after the key's colon. The [public Python SDK](https://github.com/hyperliquid-dex/hyperliquid-python-sdk/blob/4e436273ab1bec32ca9cd78918f203daaf4fc0a5/hyperliquid/info.py) corroborates the field names and JSON types.

## Resolving the initial precision

The [order-status evidence](../RE-001-node115-order-status-nested-fields/README.md) already established the shared post-format trimming and sign normalization. Its initial precision was open. The RIP-relative template reference at `0x44a61f6` selects eight bytes at `0x459898`: `c5 20 00 00 70 0a 00 00`. Compiling separate fixed-precision probes at 8, 9, 10, 11 and 12 places with official rustc 1.95.0 for Linux x86-64 selects these exact bytes only for `format!("{x:.10}")`.

The relocation at `0x64e0a78` selects `0x1688740`. All 52 bytes of that callback match the public toolchain's `f64` Display entry after masking only the two link-time jump displacements. Its two relocation targets name the shortest and exact decimal routines. The template selects the precision-bearing path. This identifies the argument type and display mode as well as the precision; the complete linked decimal conversion routines have not been byte-compared.

## Reproduce

Run from the repository root with GNU objdump in PATH (or set `OBJDUMP`), Python 3, Cargo, and official rustc 1.95.0 with its x86_64-unknown-linux-gnu standard library.

```sh
python3 research/work-items/RE-015-node115-delegator-summary-json/verify.py
python3 research/work-items/RE-015-node115-delegator-summary-json/check_amounts.py
cargo test --locked --offline --manifest-path src/info-api/Cargo.toml
```

The independent Decimal oracle checks 4,096 compact full responses, including exact rounding ties, adjacent binary64 values, signed zeros and finite extremes. It executes only the reconstructed writer. Account lookup, aggregation, and HTTP dispatch are outside this serializer's scope.
