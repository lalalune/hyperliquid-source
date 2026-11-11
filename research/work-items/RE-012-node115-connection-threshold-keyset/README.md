# RE-012: node 115 connection threshold key-set branch

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. [#5112](https://github.com/lalalune/hyperliquid-source/pull/5112) binds the first count/threshold comparison; [#5115](https://github.com/lalalune/hyperliquid-source/pull/5115) studies the second-counter route from its below-threshold branch. [#5102](https://github.com/lalalune/hyperliquid-source/pull/5102) previously describes a four-byte ordered set and lookup in a separate counting helper; this packet credits that layout and establishes the caller's selected at-or-above-threshold dispatch.

## Selected branch

Suppose the first helper returns N >= the stable threshold T and normal continuation reaches `0x5a62daf`. Its selected object has a root pointer at `+0x28` and a depth-like word at `+0x30`; the lookup key is the original `esi` dword saved by the enclosing function. For a valid stable tree sorted according to byte-swapped unsigned four-byte comparison, each node uses u16 count `+0x36`, keys at `+8 + 4*i`, and child pointers at `+0x38 + 8*i`. An equal key enters the `al=3` common-dispatch route; a null root or an exhausted search enters it with `al=0`. Normal lock release and its wake call preserve this low byte.

At the common dispatch, for original input `edx` low byte F in {0,1}, an absent key returns `al=0`; a present key with F=0 returns `al=3`, while a present key with F=1 enters the second-counter route documented in #5115. Thus this branch distinguishes key presence only after the first count reaches its threshold. The below-threshold path, which bypasses this search, is covered by #5112/#5115. These are local raw-byte/control-flow facts, not an attribution of allowlist, rejection, or source enum semantics.

The result assumes normally returning helper calls, a valid ordered tree, stable pointers and threshold, no interfering aliases, and the selected flag values. It does not prove runtime reachability, source names, concurrency safety, other paths, external effects, or that this runtime tree is identical to the one observed in #5102.

## Static verification

`PYTHONPATH=tools python research/work-items/RE-012-node115-connection-threshold-keyset/verify.py` authenticates the captured target, the complete caller FDE and selected instruction/branch pins. Corruption controls and synthetic ordered-key/dispatch arithmetic do not execute or emulate captured target instructions.
