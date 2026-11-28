# RE-009 #115 JSON context identifier counters

The selected keyed JSON Context visitor restores `next_oid`, `next_lid`, and `next_twap_id` to decoded state offsets `+0x38`, `+0x40`, and `+0x48`. The JSON path has its own key selector, byte-cursor and numeric reader. It agrees on the selected output and default with the MessagePack reader documented in [#7229](https://github.com/lalalune/hyperliquid-source/pull/7229).

| Field | Index | Unsigned scalar call | Saved value | Completion |
| --- | --- | --- | --- | --- |
| `next_oid` | 7 | `0x409d677` | `rsp+0x80` | Output `+0x38`, with a named missing-field branch when absent. |
| `next_lid` | 8 | `0x409d73d` | `rsp+0x78` | Output `+0x40`, with a named missing-field branch when absent. |
| `next_twap_id` | 9 | `0x409d5fd` | `rsp+0x8` | Output `+0x48`, with zero selected when the seen bit is clear. |

Each call reaches the same unsigned scalar reader `0x3ef2dc0` used for height. The caller stages the RDX word and sets the corresponding seen flag only on its selected successful return. A repeated field takes its own duplicate branch. At map completion `0x409d891..0x409d89e` tests the TWAP seen bit and selects the staged qword or zero.

The Locus visitor carries the first word in the upper half of its lane from the child at `+0x30`. The other two words occupy its next lane at child `+0x40`. The verifier recomputes the enclosing copy coordinates documented by the [JSON state reader](../RE-009-abci-state-read-115/README.md) for all 24 bytes. On the selected ordinary branches with the documented copy bindings, they retain their coordinates through the allocated outer result. This verification does not execute the target, determine any live counter value, or establish checkpoint replay parity.

## Reproduce

From the repository root:

```sh
python3 -B research/work-items/RE-009-node115-json-context-identifier/verify.py
```

[Offline output](offline-log.txt) | [Instruction windows](windows.txt)
