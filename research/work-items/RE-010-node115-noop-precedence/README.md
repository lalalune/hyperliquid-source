# RE-010 · Node #115 noop result and check precedence

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

For deterministic replay, treating the wire action `noop` as an unconditional success would skip observable result checks. This packet traces the selected dispatch copy into its terminal wrapper paths for [#3924](https://github.com/lalalune/hyperliquid-source/issues/3924).

The successful decoder arm loads internal tag `0x86` after calling `0x573d550`. In the execution table at `0x92671c`, subtracting `0x86` selects the first cell, which reaches `0x54a301c`. The arm forwards output, state, and a 20-byte input key to `0x5520580` at `0x54a3025`. It does not advance or pass the action payload in the fourth argument. The handler reads the key at offsets 0 and 16 and uses it in state lookups.

| Path through the wrapper | Observed result |
| --- | --- |
| Selected equality exit from the second key lookup at `0x5520986` | Returns before either check. The result starts with byte `0x0f` and stores word `0x120` at offset `0x10`. |
| State pointer at `+0x16e8` is null after key selection | Enters the two-check path at `0x5520ab5` without that lookup. |
| First check at `0x5520ae2 → 0x5551140` returns a word other than `0x1a2` | Copies the result to output offset `0x10` and writes output byte `0x0f`; skips the second check. |
| Second check at `0x5520b1c → 0x5551920` returns a word other than `0x1a2` | Copies the second check's result and writes output byte `0x0f`. The call has fifth argument zero. |
| Both checks return word `0x1a2` | Writes output byte `0x0e` and goes straight to the return epilogue. |

The two checks take an argument whose first and third qwords are both zero. The replay contract established here is the wrapper's return precedence and selected result fields. The packet does not assign wire error names, identify the complete policy of either check, or show whether these helpers mutate state.

Run `python3 research/work-items/RE-010-node115-noop-precedence/verify.py` from the repository root. The verifier checks the pinned ELF, resolves the selected decoder and execute cells, and checks the short-circuit edges. It rejects a substituted dispatch offset and a changed first-check conditional branch in memory. Inspect the linked VAs above with x86-64 objdump for the corresponding operands.
