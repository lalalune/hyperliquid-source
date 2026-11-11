# RE-010 · Node #115 order array layout and admission sequence

This packet answers a replay question from [#3924](https://github.com/lalalune/hyperliquid-source/issues/3924): which decoded fields delimit the array of order rows, and which wrapper checks must return before order processing can begin? The existing action type matcher identifies the wire name but does not recover this layout or the wrapper's short-circuit behavior.

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Decode and handoff

The decoder arm at `0x4d40468` passes the relocated field table (`orders`, `grouping`, `builder`) to `0x571e250` at `0x4d4048c`. The map path for the first field calls `0x56952c0` at `0x571e7f1`, accepts the child result only if its tag byte is `9`, and saves three words. At `0x571ed30`–`0x571ed3f` the successful path writes the three words at result offsets 0, 8 and 16. On the same finalization path an absent first field selects the literal `orders` and a separate helper at `0x571eca5`.

The parent tests the first word for the signed minimum sentinel before loading internal tag `0x94`. In the box construction path the tag goes at offset 0, while the first three words go at offsets 8, 16 and 24. The execute arm adds 8 and calls `0x550de20` at `0x54a32ca`. It uses the second word as a pointer and the third as a row count, deriving `end = begin + 56 * count`. This validates the pointer and count mapping without assuming a public numeric wire tag or a complete layout for an individual row.

## Execution wrapper

The wrapper scans rows at stride 56 and branches on byte `+0x36`. An empty range reaches preparation without reading a row. A zero flag can enter a distinct lookup path if state member `+0x16e8` is present. The flag's business meaning remains open.

| Stage | Direct call | Required return tag to continue | Other tag branch |
| --- | --- | --- | --- |
| Prepare range | `0x550e3e7 → 0x50f9e10` | `0x1a2` | `0x550e4d3` |
| First check | `0x550e437 → 0x5551140` | `0x1a2` | `0x550e560` |
| Second check | `0x550e480 → 0x5551920` | `0x1a2` | `0x550e622` |
| Downstream processing | `0x550e4c9 → 0x59d6660` | | |

This packet establishes static layout and wrapper admission. It does not establish the check helpers' policy, writes inside downstream processing, execution against a restored snapshot, or equivalence of the resulting state.

## Reproduce

Run `python3 research/work-items/RE-010-node115-order-admission/verify.py` from the repository root. The verifier authenticates the ELF, follows the selected relative cells and direct calls, checks the relocated field names, and verifies the instruction bytes supporting the pointer/count mapping and three short circuits. It repeats three checks on altered relative operands in memory. For independent inspection, disassemble the address ranges around the listed call sites with GNU objdump or LLVM objdump. No captured code is executed.
