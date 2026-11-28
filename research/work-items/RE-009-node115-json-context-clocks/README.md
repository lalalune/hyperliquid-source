# RE-009 #115 JSON checkpoint context clocks

The selected JSON checkpoint object reader carries `exchange.locus.ctx.time` and `exchange.locus.ctx.prev_time` as separate 12-byte values through the outer decoded allocation. Their coordinates are `+0x60..+0x6b` and `+0x6c..+0x77`, matching the selected MessagePack layout in [#7226](https://github.com/lalalune/hyperliquid-source/pull/7226). The earlier [JSON state read packet](../RE-009-abci-state-read-115/README.md) follows the same outer path for height but does not map these two fields.

| Field | Key and selected scalar reader call | Staging and context output |
| --- | --- | --- |
| `time` | Index 5, branch `0x409d1e0`, call `0x409d4eb`. | Dword at `rsp+0x4c`, qword at `rsp+0xf0`. Stores at `0x409cd10` and `0x409cd1b`. |
| `prev_time` | Index 6, branch `0x409d285`, call `0x409d534`. | Dword at `rsp+0x48`, qword at `rsp+0xe8`. Stores at `0x409cd23` and `0x409cd2e`. |

Both normal object paths consume the colon and call `0x3fd2100`. The selected quoted path hands string decoding to slot `0x64e08f8` and the subsequent time text conversion to `0x472e8c0`. On the selected success it returns tag zero and 12 payload bytes at result `+4..+0xf`. The object visitor takes separate duplicate and missing branches from the two saved dwords, each with the matching field-name literal.

In the selected Locus caller the result starts at `rsp+0x338`. SIMD loads read the two lanes beginning at `+0x398` and `+0x3a8`, transfer them through `+0x310/+0x320` and place them at `+0x1670/+0x1680`. The prior height packet pins the enclosing copies. Recomputing those copy ranges for the 16-byte first lane and the eight relevant bytes of the second lane preserves all 24 bytes through the Locus, Exchange and outer result. The proof assumes the selected ordinary returns and copy bindings used in the height packet.

This static evidence stops at the outer decoded allocation. It does not establish the complete accepted time string grammar, a real fixture's values or equality of replay roots.

## Reproduce

From the repository root:

```sh
python3 -B research/work-items/RE-009-node115-json-context-clocks/verify.py
```

[Offline output](offline-log.txt) | [Instruction windows](windows.txt)
