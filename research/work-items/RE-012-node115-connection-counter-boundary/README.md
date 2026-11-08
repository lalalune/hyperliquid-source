# RE-012: node 115 connection second-counter boundary

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. [#5115](https://github.com/lalalune/hyperliquid-source/pull/5115) establishes that the selected connection path calls `0x59db3a0` with amount and threshold both 1, then XORs the returned low byte with 3. [#5076](https://github.com/lalalune/hyperliquid-source/pull/5076) establishes the helper's saturating update and its <= threshold return on a different caller. This packet composes that connection-specific call with the helper's > threshold continuation and bounds both raw return bytes; it does not claim the generic update as new.

## Selected existing-entry case

Take the selected connection path of #5115, with a valid existing selected counter row, unsigned qword S immediately before the selected add, input flag 1, normal calls and valid stable storage. The helper's initial callback must return zero so that the counter path is taken. The selected update adds the argument 1 to S with unsigned saturation. Assuming no intervening helper or alias changes that qword before its later reload, the value C at the final comparison is `min(2^64-1, S+1)`.

The helper compares C to its supplied threshold 1. If C<=1 it returns low byte 0. If C>1 it calls `0x4ef8bb0`; on a nonzero low-byte result it returns 1 directly, and on zero it either skips or performs additional reporting work before returning 1 on normal completion. Therefore, after the caller's XOR, S=0 gives final `al=3`, while every S>=1 gives `al=2`, including saturation. This conditional relation is not an unconditional first/second-request claim: initial callback bypass, counter creation, intervening mutation, epoch resets and errors remain outside it.

The same helper separately updates another saturating counter, and callbacks can have effects beyond this projection. Time units, actual runtime identity, source field names, admission semantics, concurrency and delivery are not established. All referenced pointers and selected entries must be valid and stable, and helpers and lock releases must return normally.

## Static verification

`PYTHONPATH=tools python research/work-items/RE-012-node115-connection-counter-boundary/verify.py` authenticates the target, two complete FDEs, selected instruction bytes and direct call targets; synthetic boundary arithmetic and corruption controls do not execute or emulate target instructions.
