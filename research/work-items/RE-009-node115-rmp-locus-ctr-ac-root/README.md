# RE-009 #115 complete named Locus ctr.ac subtree parity

Compare the full 23-leaf `exchange.locus.ctr.ac` subtree at raw path `[0,10,6]`. The checkpoint and raw ABCI export have separate SHA-256 pins. The reference's whole raw ordered tree must reproduce its declared digest and its internal Context height leaf must reproduce H.

| Relative child | Named field | Stored projection |
|---|---|---|
| 0–3 | `p`, `m`, `l`, `L` | One LE64 each at `+0x30`, `+0x38`, `+0x40`, `+0x48` |
| 4–6 | `M`, `b`, `c` | Five LE64 leaves per branch, with child names `t`, `s`, `c`, `u`, `l` in that order |
| 7–8 | `s`, `t` | Word `n` and Time `t` in separate children. Time preimage is signed epoch seconds LE64 followed by nanos LE32. |

Named writer `0x5679120` calls the omission predicate at `0x4e44e10` and writes non-default `ac` through `0x4d95850`. The three word-group fields use `0x4e0bb40`, and the two Time pairs use `0x5184a30`. Zero words and epoch instants can be omitted. The raw visitor `0x3b83280` reaches seven word- or group-related children and two clock-pair children independently of that omission. Its nested visitors `0x3b83490` and `0x4306a30` assign distinct slots, even when their bytes are zero. Thus omitted `ac` projects a populated default raw branch with zero words and Unix-epoch timestamps. [#7782](https://github.com/lalalune/hyperliquid-source/pull/7782) independently checks the seven surrounding direct `ctr` leaves.

Use source files pinned in the scripts from [#7445](https://github.com/lalalune/hyperliquid-source/pull/7445), [#7404](https://github.com/lalalune/hyperliquid-source/pull/7404), [#7344](https://github.com/lalalune/hyperliquid-source/pull/7344), [#7368](https://github.com/lalalune/hyperliquid-source/pull/7368) and [#7352](https://github.com/lalalune/hyperliquid-source/pull/7352). Run `python -B research/work-items/RE-009-node115-rmp-locus-ctr-ac-root/verify.py --helpers PATH --rustc PATH` from the checkout root. The verifier reads the authenticated ELF and exercises synthetic populated, absent, explicit-zero and varied clock inputs. No live checkpoint, observed root, or binary execution is part of the proof.
