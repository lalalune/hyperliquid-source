# Node #115 spot account response JSON

The Info API can serialize a precomputed spot balance, outcome balance or
portfolio-margin response with the field order and omission rules recovered
from the signed Linux x86-64 node #115 artifact. The entry point is
`info_api::response::spot::write_spot_state`. It accepts existing decimal text
for display quantities. The native formatter's original binary64 rounding is
a separate boundary.

## Native field contracts

| Record | Complete native serializer FDE | Field order |
| --- | --- | --- |
| Spot account | `0x2f0eb30..0x2f0ed5c` | portfolioMarginEnabled, balances, evmEscrows, portfolioMarginRatio, tokenToPortfolioBorrowRatio, tokenToPortfolioSupplyRatio, tokenToAvailableAfterMaintenance |
| Balance | `0x2f0e8c0..0x2f0eb2b` | coin, token, total, hold, entryNtl, spotHold, ltv, borrowed, supplied |
| EVM escrow | `0x2f0e770..0x2f0e8b6` | coin, token, total |

The field-name pointer, literal length and direct writer at each arm are
regenerated from the FDE disassembly. The parent invokes the account writer at
`0x2efe5a1`. The two vector writers call the row and escrow serializers in
iteration order. The account emits `balances` even when empty, emits a true
portfolio-margin flag only, skips empty escrow vectors, and uses independent
presence checks for the ratio and all three token maps. For the latter fields
the outer test against `0x8000000000000001` suppresses an absent map before
the shared value writer can emit a generic null. A present empty map emits
`[]`. The map writer iterates integer keys and string values as ordered pairs.
Token 0 and present zero-valued decimals remain valid fields. Missing optional
row values are omitted.

All three required balance numbers are emitted through the same field writer
at `0x2ebfd30`; the value path at `0x2edf980` reads binary64, invokes the
formatter and quotes its escaped output. The public writer accepts that output
as its input and propagates host I/O errors. This covers the JSON shape while
keeping account lookup, checkpoint restoration, margin calculations and binary64
formatting outside the claim. The example HTTP server's placeholder route is
not wired to this serializer because its reconstructed state does not retain
all required account inputs across restarts.

Hyperliquid documents the ordinary balance shape and a three-row account
example containing USDC, PURR and an outcome token. The independent TypeScript
SDK also publishes the optional margin, escrow and token-pair shapes. The
Rust tests use the official example values and independently exercise an
extended response, absent versus zero fields, UTF-8 escaping and partial
writer failure.
[Official spot account response](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/info-endpoint/spot)
· [Published client schema](https://jsr.io/@nktkas/hyperliquid/doc/api/info)

## Reproduction

From the repository root, with Python 3 and Capstone 5.0.7:

```sh
packet=research/work-items/RE-012-node115-spot-state-json-schema
python3 "$packet/verify.py" | diff - "$packet/records.json"
cargo test --locked --offline --manifest-path src/info-api/Cargo.toml
cargo clippy --locked --offline --manifest-path src/info-api/Cargo.toml --all-targets -- -D warnings
```

The static check authenticates the full target SHA-256, reads its actual unwind
extents, and checks branch and call targets from instruction-aligned disassembly.
The repository's component-wide progress gates are unchanged. New reconstruction
code and tests are independently authored under the root MIT license.
