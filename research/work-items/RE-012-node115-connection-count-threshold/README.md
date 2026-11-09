# RE-012: node 115 connection count threshold

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This packet follows the caller-side threshold check identified as a next question in [#5102](https://github.com/lalalune/hyperliquid-source/pull/5102); that work already observes the 8–100 clamp and studies the separate counting helper `0x4fabf60`. The result here adds the absent-option default, exact boundary comparison, and the selected local continuation. [#4345](https://github.com/lalalune/hyperliquid-source/pull/4345) binds upstream callers of this larger function, and `RE-001-node115-connection-gossip-reload-lock` separately studies its earlier reload synchronization.

## Selected threshold and count branch

At `0x5a62b6f`, let P be the selected object in `r14`. If byte `[P]` is zero, the function stores threshold T=8. Otherwise it reads unsigned qword X at `[P+8]` and stores `T = min(100, max(8, X))` at `[rsp+0x70]`. The equal case X=T skips a local formatting call; unequal takes that call before continuing. This is not proof of what the call emits or whether a log is delivered.

On the selected normal continuation, with the threshold slot not modified by intervening calls, `0x5a62cd8` calls `0x4fabf60`; let N be its returned unsigned qword. The branch at `0x5a62cdd` takes the `0x5a62d10` path when N >= T, including equality, and otherwise assigns `al=3` and enters the selected release/common-dispatch path. The normal release wake branch preserves that `al` over its indirect call. `al=3` is a local intermediate value, not an unconditional final return or a proven admission/rejection status: the later dispatch also depends on incoming and state flags. #5102's interpretation of the helper's count is credited context, not independently reproduced here.

These observations assume valid pointers, stable threshold storage and normally returning helper/formatting calls. They do not establish the source name or unit of X, the helper's full semantics, concurrency properties, all caller paths, external effects or a full connection policy.

## Static verification

`PYTHONPATH=tools python research/work-items/RE-012-node115-connection-count-threshold/verify.py` authenticates the target and two complete FDE bodies, selected instruction bytes and the direct count call. Synthetic unsigned boundary checks and selected corruption controls are arithmetic/static only; no captured instructions are executed or emulated.
