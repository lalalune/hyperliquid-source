# RE-010 · Node #115 scheduleCancel optional-time wrapper limit

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The existing schedule-cancel packet documents the volume gate and expiry map in two other execute paths. This packet recovers the range rejection in the wrapper at `0x55052a0` before the wrapper enters the core at `0x5569c10`. The related diagnostic edge in [#4039](https://github.com/lalalune/hyperliquid-source/pull/4039) is inside the core, outside the recovered wrapper.

The selected decoder call at `0x4d412fc` reaches `0x57389f0`. Successful decoding selects tag `0x98`. Execute cell 18 takes `0x54a3616`, which loads the two payload words at Action offsets 8 and 16 directly into the fourth and fifth arguments to the wrapper. The wrapper saves these words at entry.

After the two check helpers return `0x1a2`, the wrapper compares the second payload word unsigned to `0x0ccccccccccccccb`. The reject predicate is exactly `(word0 & 1) != 0 && word1 > 0x0ccccccccccccccb`. On that path the wrapper emits outer byte `0x0f`, word `0x154` at output offset `0x10`, and value 1 at offset `0x18`. Otherwise it calls `0x5569c10`. A returned word `0x1a2` gives output byte `0x0e`; another return word leads to error result copying. The threshold is inclusive on the handoff path and is ignored if the presence bit is clear.

The evidence establishes selected precedence and raw output coordinates. It does not infer a public error string from `0x154` or qualify writes performed by the core.

Run `python3 research/work-items/RE-010-node115-schedule-time-range/verify.py` from the repository root. It checks the authenticated image, selected cells, argument loads, literal comparison and branch targets. Negative controls change the bound, conditional branch and core call operand without executing captured code.
