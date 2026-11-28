# RE-009 #115 parsed checkpoint time components

The [JSON clock format packet](https://github.com/lalalune/hyperliquid-source/pull/7237) identifies the time constructor called after parsing the checkpoint clock string. This packet traces its selected normal result to three 32-bit words. It follows the date producer's packed word, seconds of day, and fractional nanoseconds independently.

| Constructor output | Selected source |
| --- | --- |
| `+0x0` | Upper dword returned by the date helper `0x1627430`; taken by the shift at `0x1628397`. |
| `+0x4` | `3600 * (12 * period + hour_in_period) + 60 * minute + second`. The two multipliers are at `0x16283a2` and `0x16283a8`. |
| `+0x8` | The fractional nanosecond word, plus a one-billion bias on the second-60 branch. |

The selected ordinary calendar path has no independent Unix timestamp in the parsed record, so it bypasses the timestamp cross-check at `0x16283ed`. On the second-60 path `0x1627f00` substitutes 59 for the seconds contribution and `0x1627f06` supplies the bias added at `0x1627f31`. The JSON adapter copies those same twelve bytes to result `+4..+0xf` after the constructor returns.

The log checks three ordinary times and a second-60 example using arithmetic constants decoded from the ELF. These are synthetic arithmetic checks. They do not execute the adapter, establish the entire date helper or prove validation of a specific historical leap-second date.

## Reproduce

From the repository root:

```sh
python3 -B research/work-items/RE-009-node115-time-component-projection/verify.py
```

[Offline output](offline-log.txt) | [Instruction windows](windows.txt)
