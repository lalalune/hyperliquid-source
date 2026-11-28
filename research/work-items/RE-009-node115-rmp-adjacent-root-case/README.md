# RE-009 · Verify a named node #115 checkpoint against adjacent Context roots

This runner starts with a pinned named MessagePack checkpoint at H, a separately pinned admitted replay header at H+1, and one raw ABCI export at each height. It derives the restored Context directly from the checkpoint bytes. No hand-authored intermediate Context is needed.

At H it compares all thirteen ordered Context children, including the hardfork pair, transaction index, identifier counters and clock pair. At H+1 it compares the four begin-derived children for height, admitted round, current clock and previous clock. Both supplied raw reference trees must first reproduce their own recorded digest. The output preserves both reference digests, reports H Context differences by field, and reports the four H+1 field results separately. An H-only counter mismatch or an H+1-only clock mismatch therefore stays visible even when the other part succeeds.

The runner uses the published [streaming checkpoint projection](https://github.com/lalalune/hyperliquid-source/pull/7445), [named field normalizer](https://github.com/lalalune/hyperliquid-source/pull/7368), [thirteen-child Context model](https://github.com/lalalune/hyperliquid-source/pull/7352), [adjacent begin projection](https://github.com/lalalune/hyperliquid-source/pull/7420), and [raw tree codec](https://github.com/lalalune/hyperliquid-source/pull/7404). Each helper is pinned to its published source SHA-256. This case composes those checks from the original checkpoint file and compares the full H Context rather than only the four fields consumed by the begin projection.

| Manifest field | Input |
| --- | --- |
| `height` | Unsigned checkpoint height H |
| `checkpoint_rmp` | Decoded named checkpoint `.rmp` bytes |
| `successor_header` | JSON with explicit H+1 archive height, admitted `round`, and normalized `time` |
| `reference_h` | Native three-field `abci_hashes` row retaining the H reduction tree |
| `reference_h_plus_one` | Same export type at H+1 |

The last four fields each specify `{"path":"relative-file","sha256":"64 lowercase hex digits"}`. The case itself is also pinned. A normalized clock contains `unix_seconds` and `subsec_nanos`. For a decoded replay header, use the admitted round rather than the separate parent round, as established by [#7370](https://github.com/lalalune/hyperliquid-source/pull/7370). The runner checks explicit adjacency and the supplied bytes. It does not establish artifact origin, execute actions, or reconstruct state outside the reported fields. A valid H+1 root can differ from the begin projection because later logic may update those fields. No actual H/H+1 fixture was available.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Native evidence baseline `2da45cb0a761cff6b478e40421699857d87a94df`.

## Reproduce

Run from the repository root. For the composed fixture, place the five linked packet directories below one helper directory and use Python with `msgpack 1.1.2` and Rust 1.95. The test compiles the published raw BLAKE3 helper from #7404.

```sh
packet=research/work-items/RE-009-node115-rmp-adjacent-root-case
python3 -B "$packet/verify.py"
python3 -B "$packet/verify.py" --helpers HELPERS_DIRECTORY
python3 -B "$packet/compare_case.py" HELPERS_DIRECTORY HASH_TREE_HELPER \
  CASE.json CASE_SHA256
```

The helper executable is built using [the #7404 documented command](https://github.com/lalalune/hyperliquid-source/pull/7404). Exit 0 indicates all selected H/H+1 comparisons passed, 1 a measured selected-field difference, and 2 an invalid input. The [measured offline log](offline-log.txt) includes native writer/encoder and begin checks and the synthetic case results.
