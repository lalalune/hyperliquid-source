# RE-009 #115 named vtg empty tracker root comparison

Compare the complete raw slot 32 subtree for a named RMP `exchange.vtg` with no tracked records at an exact checkpoint height. The named checkpoint and independent raw export use separate SHA-256 pins. The reference tree must reproduce its declared raw digest before the scoped comparison runs.

The named Exchange writer at `0x54812a0` passes `+0x3d40` through `0x56784c0` to `0x5372500`. Its three named fields are `name`, `hsc` and `i`. The slot 32 visitor `0x57c0c70` preserves this order, passing source base, a zero-width source address at `+0x38`, and tracked records at `+0x18` respectively.

| Raw path | Empty tracking-state projection |
|---|---|
| `[32,0]` | BLAKE3 of the exact UTF-8 tracker name bytes. `0x141b610` passes the pointer and length to the raw update helper. |
| `[32,1]` | An initialized empty branch. Constructor `0x14ceaa0` sets its child count to zero; visitor `0x14ceac0` appends no bytes. |
| `[32,2]` | A branch with count leaf at child 2. Empty record count takes no rows through child 0 or 1 in `0x4da1ba0`; both retain their initial absent state. The count's primitive writer receives an eight-byte zero. |

Files and exact helper source pins from [#7445](https://github.com/lalalune/hyperliquid-source/pull/7445) and [#7404](https://github.com/lalalune/hyperliquid-source/pull/7404) are encoded in `compare_empty_tracker.py`. Use `python -B research/work-items/RE-009-node115-rmp-vtg-empty-root/verify.py --helpers PATH --rustc PATH` from the checkout root. The verifier authenticates the #115 ELF and uses synthetic controls for empty, ASCII and multibyte names as well as incorrect raw structure and stale digest. The ELF is never executed. This covers the complete branch for the specified empty-record input. Populated tracker state and real network checkpoint parity remain unverified.
