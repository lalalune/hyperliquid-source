# RE-010 · Node #115 updateLeverage classifier handoff

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

This packet establishes where the selected `updateLeverage` replay path classifies the payload and how it chooses the downstream result. The Action matcher alone provides no such execution contract.

The decoder at `0x56f2c30` receives field names `asset`, `isCross` and `leverage` from relocated table `0x64a3318`. The parent loads two words from the decoder's successful result and selects internal tag `0xad`. Dispatch cell 39 at `0x92671c` selects `0x54a3702`; its call at `0x54a3712` reaches `0x552b730` with the payload at Action offset eight. After both wrapper checks return word `0x1a2`, call site `0x552bd89` enters `0x514ba20`.

The latter reads two 32-bit words from payload offsets 0 and 4 and a byte from offset 8. It sends the second word and two state-derived addresses to the slot at `0x64e5b38`, which relocates to `0x46aac00`. The selected path distinguishes three cases.

| Classifier result | Observed continuation |
| --- | --- |
| Word other than `0x1a2` | Copy classifier result into output at offset `0x10` and write output byte `0x0f`. |
| Word `0x1a2` and kind at classifier result offset `+8` equals 1 | Write word `0x174` at output offset `0x10`, copy the classifier word at result offset `+0x10` to output `+0x18`, and write output byte `0x0f`. |
| Word `0x1a2` and kind differs from 1 | Call `0x556a2a0` with the classifier qword at result offset `+0x10`, zero-extended byte and first payload word in arguments four, five and six. Its result word `0x1a2` gives output byte `0x0e`; other values are copied under byte `0x0f`. |

This is static evidence for the input lanes and classifier-dependent handoff. The argument values are identified by offset here. This packet does not assign semantics to all classifier outputs or qualify writes and rollback inside the downstream operation.

Run `python3 research/work-items/RE-010-node115-leverage-dispatch/verify.py` from the repository root. It authenticates the target ELF, checks the field table and relative edges and rejects two altered branch instructions in memory.
