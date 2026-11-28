# RE-017 #115 JSON checkpoint round source

On the selected JSON object path, either `exchange.locus.ctx.round` or its alias `consensus_round` supplies decoded state `+0x30`. If neither occurs, this path writes zero. The separate height value at `+0x28` retains the producer documented in the [earlier JSON state packet](../RE-009-abci-state-read-115/README.md), which also pins the enclosing copy chain.

- In JSON key selector `0x41fc4a0`, the five-byte arm compares `round`. The fifteen-byte arm compares `consensus_round` using overlapping eight-byte reads at offsets 0 and 7. Both successful routes set index 4 at `0x41fc695`. Table entry 4 selects `0x409cecf`. The same seen flag at `rsp+0xe0` is tested for either spelling; a second occurrence through either spelling reaches the duplicate handler with literal `round`.
- After the colon, `0x409d578` calls the same unsigned JSON scalar parser used for height. The caller stages RDX at `rsp+0x88`. When result bit 0 is set, the caller leaves on the error branch. Otherwise it marks the round present. At completion `0x409d824..0x409d834` selects the staged value or zero, and `0x409ccdd` writes it to result `+0x30`.
- The selected Locus read at `0x41136ab` starts its 16-byte lane at the round word. The lane moves through `rsp+0x2e0` to `rsp+0x1640`. The verifier recomputes the prior bulk-copy offsets for this specific word. Every selected Locus, Exchange and outer copy preserves its relative coordinate. This assumes normal returns and the ordinary copy slot binding documented by the height packet.

The selected [MessagePack round source](../RE-017-node115-checkpoint-round-source/README.md) establishes matching keyed read behavior and follows the round into the normal loaded state. The JSON evidence here stops at the decoded allocation. It neither derives the round from height nor establishes real fixture values or a matching replay root.

## Reproduce

From the repository root:

```sh
python3 -B research/work-items/RE-017-node115-json-replay-round/verify.py
```

[Offline output](offline-log.txt) | [Instruction windows](windows.txt)
