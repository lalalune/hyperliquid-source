# RE-017 #115 replay begin stores for compact and expanded fixtures

The [restore loader](https://github.com/lalalune/hyperliquid-source/pull/7390) stops before replay. The [clock projection](https://github.com/lalalune/hyperliquid-source/pull/7342) handles the two clocks at the start of begin. This adapter models two subsequent direct store groups, including the round destinations that differ between compact and expanded state. It accepts already admitted replay input and a pinned state image at the selected boundary.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

| Selected stage | Shared stores | Layout-specific copies |
| --- | --- | --- |
| `after-clock` | At `0x54838d3` or `0x5483fd3`, saturating-increment state `+0x28`, clear the qword at `+0x00`, and copy the admitted round to `+0x30`. The next qword at `+0x08` stays as supplied. | Compact copies the round to `+0xe08/+0xf28`. Expanded copies it to `+0x1978/+0x1a98`. |
| `before-action-initializer` | At `0x5483e0e` or `0x548452e`, write 1 at `+0x00` and zero at `+0x08`. These are the raw option words for the initial transaction index on the selected path. | A following call through `0x64e4f00` receives state `+0x40c0` or `+0x4c30`. Its effects are outside this adapter. |

The [begin-block analysis](../RE-017-abci-preflight-result-115/README.md) records the compact ordering, and the [layout analysis](../RE-008-abci-box-layouts-115/README.md) identifies the two allocated sizes. The focused verifier checks the direct stores and both producer call sites. Round mirrors in this adapter are distinct from the earlier native loader's copies. The incoming round is explicit because the original wide replay input, its admission and the clock rotation belong to other stages.

## Reproduce offline

```sh
python3 -B research/work-items/RE-017-node115-begin-replay-stores/verify.py
python3 -B research/work-items/RE-017-node115-begin-replay-stores/test_begin.py
python3 -B research/work-items/RE-017-node115-begin-replay-stores/apply_begin.py \
    restored.bin --sha256 EXPECTED_STATE_SHA256 --layout compact --height H \
    --stage after-clock --new-round ADMITTED_ROUND > first-begin-stores.bin
```

The input height identifies the supplied stage image. For the later stage, supply the post-begin image at its own height and result digest, omitting the incoming-round option. The tests compare the full output image in both layouts, including untouched bytes, check height saturation and use a real local temporary file through the CLI. See the [offline log](offline-log.txt).

The two groups are separated by native logic and checks. The adapter does not execute those helpers, follow captured pointers, apply actions or establish H+1 state-root parity.
