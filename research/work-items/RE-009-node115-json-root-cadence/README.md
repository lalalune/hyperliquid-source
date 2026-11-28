# RE-009 #115 JSON checkpoint root cadence

The selected JSON object path carries `exchange.msc.aci` to the periodic root divisor at state `+0x39c8`. This is a separate parser and copy route from the MessagePack reader in [#7235](https://github.com/lalalune/hyperliquid-source/pull/7235), with the same selected value and layout at the materializer.

1. Exchange object table entry 58 selects `0x3efba62`. Its duplicate handler names `msc`. After consuming the colon, call `0x3efd286` enters JSON child `0x400cec0`.
2. The child table entry 11 selects `0x400d161`, whose duplicate handler names `aci`. After the colon, `0x400da69` calls scalar reader `0x3fd23d0`. The child stages RDX at `rsp+0x90` and sends result tag 1 to its error exit.
3. The selected map completion reads the staged word and selects it if nonzero. Otherwise the initialized value of 1,000 stays in RSI. The output copy sequence carries it from `rsp+0x3e8` to child result `+0xc0`. The Exchange copies and the [outer JSON state reader](../RE-009-abci-state-read-115/README.md) retain the word at decoded state `+0x1ea8`.
4. The materializer copies historical `+0x1de8..+0x1edf` to live `+0x3908..+0x39ff`. The word at the resulting `+0x39c8` is read at `0x5a07f85` on the selected periodic root branch.

This evidence is conditional on the ordinary object path and the documented copy bindings. It does not cover the positional JSON route, the complete scalar grammar or a particular live checkpoint.

## Reproduce

From the repository root:

```sh
python3 -B research/work-items/RE-009-node115-json-root-cadence/verify.py
```

[Offline output](offline-log.txt) | [Instruction windows](windows.txt)
