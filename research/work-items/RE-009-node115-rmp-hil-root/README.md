# RE-009 #115 named checkpoint hil to raw ABCI subtree

Compare the full ordered slot 51 subtree at height H for a SHA-256-pinned named RMP checkpoint and a separately pinned raw ABCI export. This adds a four-field branch to the checkpoint-to-root evidence path and reports field-level diagnostics. The verifier uses synthetic controls. No actual checkpoint, successor block, or measured root is supplied.

The serialized `exchange.hil` writer gets Exchange `+0x3830` at `0x5481558` and emits a named four-field structure in `0x5677610`. Slot 51 reaches `0x44f3030`; that visitor supplies four one-child entries in this order to `0x41ad9a0` at `0x44f30e1`.

| Child | Named field | Offset | Raw path |
|---|---|---|---|
| 0 | `m` | `+0x20` | One-child branch, word at child 0; native enum `e=0, x=1, d=2` |
| 1 | `half_life` | `+0x0` tag, `+0x8` payload | nil gives only child 1 with word 0; Some gives binary64 bits at child 0, word 1 at child 1 |
| 2 | `max_slippage` | `+0x10` | raw little-endian binary64 bits |
| 3 | `max_n_depositors` | `+0x18` | raw little-endian unsigned word |

The named mode branches start at `0x56776d5`; visitor `0x44ebe70` stages the corresponding little-endian word for the primitive writer. The optional visitor `0x4514d70` supplies the two row groups to `0x41ae280`; cap and binary64 visitors resolve to the qword and binary64 byte writers. Finite binary64 and explicit nil are the verified named input subset. Signed zero stays distinct.

Reuse the unchanged helpers from [#7445](https://github.com/lalalune/hyperliquid-source/pull/7445) and [#7404](https://github.com/lalalune/hyperliquid-source/pull/7404) in the directory layout pinned by `compare_hil.py`. From the checkout root with the committed #115 artifact available, run `python -B research/work-items/RE-009-node115-rmp-hil-root/verify.py --helpers PATH --rustc PATH` using Python 3 and msgpack 1.1.2. Only repository source and the byte-pinned hash driver compile. The captured executable is read for static evidence. A local hash driver plus ordinary synthetic files exercise the full comparison and CLI mismatch status.
